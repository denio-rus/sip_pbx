defmodule SipPbx.SIP.Transport do
  @moduledoc """
  UDP-сокет АТС и демультиплексор SIP-сообщений: принимает пакеты, сверяет
  бан-лист, по реестру транзакционных ключей (`:sip_pbx_tx_reg`, ETS `:public`,
  владелец — этот процесс) раскладывает их между транзакциями и роутером
  (`{:sip_new_request | :sip_2xx, msg, from}`), остальное — владельцу ключа
  (`{:tx_dup | :tx_resp, msg, from}`). Каждый приём/отправка — запись в
  `SipPbx.LogBuffer` и счётчик в `SipPbx.Metrics`.

  Формы API с `server` — для юнит-тестов с именованным экземпляром
  (`port: 0`), боевые — ходят по имени `__MODULE__`. Реестр сознательно
  не `:named_table`: экземпляров может быть несколько (тесты поднимают свой),
  имя — только для диагностики. Читатели реестра с чужой стороны (Task 9/13)
  в окно перезапуска Transport получат мёртвый tid — обязаны терпеть.
  """

  use GenServer

  alias SipPbx.{Alerts, LogBuffer, Metrics}
  alias SipPbx.SIP.Message

  # аналог inet:ip_address()/inet:port_number(): Elixir не резолвит удалённые
  # типы Erlang-модулей в spec'ах, поэтому кортежи расписаны явно (как в Alerts)
  @type ip ::
          {0..255, 0..255, 0..255, 0..255}
          | {0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535,
             0..65_535}

  @typedoc "Источник пакета / цель отправки: адрес UDP-пиров."
  @type from :: {ip(), 0..65_535}

  @typedoc "Транзакционный ключ: `{:srv, branch, метод, cseq, from}` или `{:cli, branch}`."
  @type tx_key :: term()

  @typedoc """
  Роль транзакции-владельца: серверная, клиентская INVITE (её 2xx уходят
  роутеру, §17.1.1.3) или прочая клиентская.
  """
  @type tx_kind :: :srv | :cli_invite | :cli_other

  @type server :: GenServer.server()

  # ------------------------------------------------------------------ API

  @doc """
  Запустить транспорт: `:port` (по умолчанию env `:sip_port`), `:router` —
  pid или имя процесса, получающего новые запросы и 2xx на INVITE, `:name`
  (по умолчанию `__MODULE__`). Сокет `active: true` — пакеты приходят почтой.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Отправить SIP-пакет (iodata) в `target` через сокет транспорта; журнал
  `:out` и счётчик `:pkt_out` — на успешной отправке.
  """
  @spec send_msg(from(), iodata()) :: :ok | {:error, term()}
  def send_msg(target, data), do: send_msg(__MODULE__, target, data)

  @doc "То же, но с указанием экземпляра транспорта (юнит-тесты)."
  @spec send_msg(server(), from(), iodata()) :: :ok | {:error, term()}
  def send_msg(server, target, data) do
    GenServer.call(server, {:send, target, data})
  end

  @doc """
  Зарегистрировать транзакционный ключ за процессом (`{pid, kind}`);monitor
  за `pid`: по `{:DOWN, ...}` все его ключи вычищаются — транспорт не должен
  доставывать дубликаты мёртвой транзакции.
  """
  @spec reg_tx(tx_key(), pid(), tx_kind()) :: :ok
  def reg_tx(key, pid, kind), do: reg_tx(__MODULE__, key, pid, kind)

  @doc "То же, но с указанием экземпляра транспорта (юнит-тесты)."
  @spec reg_tx(server(), tx_key(), pid(), tx_kind()) :: :ok
  def reg_tx(server, key, pid, kind) do
    GenServer.call(server, {:reg_tx, key, pid, kind})
  end

  @doc "Снять ключ из реестра (снимался уже или нет — `:ok`)."
  @spec unreg_tx(tx_key()) :: :ok
  def unreg_tx(key), do: unreg_tx(__MODULE__, key)

  @doc "То же, но с указанием экземпляра транспорта (юнит-тесты)."
  @spec unreg_tx(server(), tx_key()) :: :ok
  def unreg_tx(server, key), do: GenServer.call(server, {:unreg_tx, key})

  @doc "Число зарегистрированных ключей (для инвариантов тестов и лимита 503)."
  @spec tx_count(server()) :: non_neg_integer()
  def tx_count(server \\ __MODULE__), do: GenServer.call(server, :tx_count)

  @doc """
  Владелец ключа: pid транзакции или `nil`. Читалка реестра для матчинга CANCEL
  по §16.10 (Proxy, Task 13) — по ключу живой IST того же диалога. В окно
  перезапуска транспорта call даёт exit `:noproc` — звать только из процессов,
  для которых это приемлемо.
  """
  @spec lookup_tx(server(), tx_key()) :: pid() | nil
  def lookup_tx(server \\ __MODULE__, key), do: GenServer.call(server, {:lookup_tx, key})

  @doc "Боевой порт сокета (актуально при `port: 0` в тестах)."
  @spec local_port(server()) :: :inet.port_number()
  def local_port(server \\ __MODULE__), do: GenServer.call(server, :local_port)

  # ---------------------------------------------------------------- Server

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, Application.fetch_env!(:sip_pbx, :sip_port))
    router = Keyword.fetch!(opts, :router)

    # без packet: — пакетные опции :gen_udp здесь не нужны и на OTP 27 ломают
    # открытые варианты конфига (gotcha sip_phone)
    case :gen_udp.open(port, [:binary, active: true]) do
      {:ok, sock} ->
        # не :named_table: экземпляров транспорта несколько (боевой + тесты),
        # :public — реестр читают напрямую транзакции (Task 9)
        tab = :ets.new(:sip_pbx_tx_reg, [:set, :public, read_concurrency: true])
        {:ok, %{sock: sock, router: router, tab: tab}}

      {:error, reason} ->
        {:error, {:udp_open, reason}}
    end
  end

  @impl true
  def handle_call({:send, {ip, port}, data}, _from, state) do
    raw = IO.iodata_to_binary(data)

    case :gen_udp.send(state.sock, ip, port, raw) do
      :ok ->
        LogBuffer.add(:out, first_line(raw), raw)
        Metrics.incr(:pkt_out)
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:reg_tx, key, pid, kind}, _from, state) do
    :ets.insert(state.tab, {key, {pid, kind}})
    Process.monitor(pid)
    {:reply, :ok, state}
  end

  def handle_call({:unreg_tx, key}, _from, state) do
    :ets.delete(state.tab, key)
    {:reply, :ok, state}
  end

  def handle_call(:tx_count, _from, state), do: {:reply, :ets.info(state.tab, :size), state}

  def handle_call({:lookup_tx, key}, _from, state) do
    case :ets.lookup(state.tab, key) do
      [{^key, {pid, _kind}}] -> {:reply, pid, state}
      [] -> {:reply, nil, state}
    end
  end

  def handle_call(:local_port, _from, state) do
    {:ok, port} = :inet.port(state.sock)
    {:reply, port, state}
  end

  @impl true
  def handle_info({:udp, _sock, ip, port, data}, state) do
    Metrics.incr(:pkt_in)
    receive_packet(data, {ip, port}, state)
    {:noreply, state}
  end

  # DOWN по монитору из reg_tx: вычищаем все ключи умершего владельца;
  # шаблоны по обоим аритетам ключей (srv — 5-кортеж, cli — 2-кортеж)
  def handle_info({:DOWN, _ref, :process, pid, _}, state) do
    :ets.match_delete(state.tab, {{:_, :_, :_, :_, :_}, {pid, :_}})
    :ets.match_delete(state.tab, {{:_, :_}, {pid, :_}})
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------ приёмка

  defp receive_packet(data, from, state) do
    case Message.parse(data) do
      {:error, _reason} ->
        # битый пакет не должен отличать от атаки: просто журнал + счётчик
        Metrics.incr(:parse_fail)
        LogBuffer.add(:info, "не разобрано: " <> first_line(data), data)

      {:ok, msg} ->
        LogBuffer.add(:in, Message.summary(msg), data)

        if blocked?(elem(from, 0)) do
          Metrics.incr(:pkt_dropped_banned)
        else
          route(msg, data, from, state)
        end
    end
  end

  # Alerts.blocked?/1 читает ETS-бан-лист напрямую; в окно перезапуска Alerts
  # таблицы нет и чтение даёт :badarg — на пути пакетов это не роняет транспорт,
  # считаем IP небаненым (carry из ревью Task 6)
  defp blocked?(ip) do
    Alerts.blocked?(ip)
  rescue
    ArgumentError -> false
  end

  defp route(%Message{type: :request} = msg, _data, from, state) do
    key = srv_key(msg, from)

    case :ets.lookup(state.tab, key) do
      [{^key, {pid, _kind}}] ->
        Metrics.incr(:pkt_dup)
        send(pid, {:tx_dup, msg, from})

      [] ->
        send(state.router, {:sip_new_request, msg, from})
    end
  end

  defp route(%Message{type: :response} = msg, data, from, state) do
    case :ets.lookup(state.tab, {:cli, Message.branch(msg)}) do
      [{_key, {pid, kind}}] ->
        # §17.1.1.3: 2xx на INVITE обходит транзакцию — её завершает диалог,
        # ответ нужен роутеру
        if kind == :cli_invite and msg.status_code in 200..299 do
          send(state.router, {:sip_2xx, msg, from})
        else
          send(pid, {:tx_resp, msg, from})
        end

      [] ->
        LogBuffer.add(:info, "ответ без транзакции: " <> Message.summary(msg), data)
    end
  end

  # Ключ серверной транзакции для входящего запроса. ACK транзакций не заводит,
  # но матчится тем же TxServer-ключом; метод в ключ берётся из CSeq ответа,
  # к которому ACK относится («2 INVITE» → «ACK:INVITE»), иначе ACK к CANCEL
  # и к INVITE с одним номером CSeq столкнулись бы на одном ключе.
  defp srv_key(msg, from) do
    {cseq_num, cseq_method} =
      case Message.cseq(msg) do
        {n, m} -> {n, m}
        nil -> {nil, nil}
      end

    method =
      case {msg.method, cseq_method} do
        {"ACK", m} when is_binary(m) -> "ACK:" <> m
        {"ACK", _} -> "ACK:"
        {m, _} -> m
      end

    {:srv, Message.branch(msg), method, cseq_num, from}
  end

  defp first_line(raw), do: raw |> String.split("\r\n") |> hd()
end

defmodule SipPbx.SIP.RouterSink do
  @moduledoc """
  Временный роутер транспорта: глушит всё (`handle_info/2` — no-op). Живого
  трафика в тестах Tasks 7–10 нет; в Task 11 его сменит Registrar,
  в Task 13 — Proxy.
  """

  use GenServer

  @doc "Запустить поглотитель сообщений под именем `__MODULE__`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts), do: {:ok, %{}}

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}
end
