defmodule SipPbx.Alerts do
  @moduledoc """
  Алерт-правила и бан-лист IP: хранит активные алерты с дребезгом (повторный
  `fire/2` пока алерт активен — не дублирует событие) и баны, раз в секунду
  проверяет метричные правила по снимку `SipPbx.Metrics`. Писатель — Auth
  (Task 10: `auth_burst` + бан по digest-фейлам), читатель — веб-консоль
  (Task 14: `/api/alerts`, `/api/blocked`, разбан командой).

  Хранение — две ETS: `:sip_pbx_alerts_state` (приватная, rule →
  `%{data, since, state: :active | :acked}`) и `:sip_pbx_banned` (`:public`,
  ip → unblock_at). `blocked?/1` вызывается с пути обработки пакетов, поэтому
  читает ETS напрямую без GenServer'а и лениво снимает просроченные bans.
  Пороги правил — env `:alert_rules`, перечитываются каждый тик.
  """

  use GenServer

  alias SipPbx.{Metrics, PubSub}

  @state_table :sip_pbx_alerts_state
  @ban_table :sip_pbx_banned
  @tick_ms 1_000

  # доля таймаутов имеет смысл только на достаточной выборке завершённых
  # транзакций — иначе одно потерянное письмо даёт 100 %
  @tx_min_completed 10

  # значения по умолчанию; env `:alert_rules` перекрывает их целиком или
  # частично (Keyword поверх дефолтов — тесты подменяют env одним ключом)
  @default_rules [
    beam_mem_mb: 512,
    reg_failure_window_s: 60,
    reg_failure_n: 5,
    tx_timeout_window_s: 30,
    tx_timeout_pct: 30,
    retrans_per_s: 20
  ]

  # аналог inet:ip_address()/inet:port_number(): Elixir не резолвит удалённые
  # типы Erlang-модулей в spec'ах, поэтому кортежи расписаны явно
  @type ip ::
          {0..255, 0..255, 0..255, 0..255}
          | {0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535,
             0..65_535}

  @typedoc "Активный алерт: правило, данные срабатывания, момент перехода в «активно» (мс)."
  @type alert :: %{rule: atom(), data: map(), since: integer()}

  @typedoc """
  Строка истории — все правила, срабатывавшие хотя бы раз: алерт плюс
  текущий статус (`:active` — не подтверждён, `:acked` — подтверждён).
  """
  @type history_entry :: %{rule: atom(), data: map(), since: integer(), state: :active | :acked}

  @typedoc "Бан: ip → абсолютный момент разбана в мс."
  @type ban :: %{ip: ip(), until: integer()}

  @doc """
  Запустить обработчик алертов: создать ETS-таблицы состояния и банов,
  завести тик проверки метричных правил каждые #{@tick_ms} мс.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Перевести правило в «активно»: broadcast `{:alert_active, rule, data}` в
  топик `:alert`. Дребезг: пока алерт активен, повторный `fire/2` ничего не
  рассылает и не обновляет `since` — событие должно быть одно на эпизод.
  `auth_burst` поднимает Auth, `blocked_ip` — `block_ip/2`.
  """
  @spec fire(atom(), map()) :: :ok
  def fire(rule, data \\ %{}) do
    GenServer.call(__MODULE__, {:fire, rule, data})
  end

  @doc """
  Подтвердить алерт: снять активность, правило может сработать снова.
  Подтверждение правила, которое не срабатывало, — тоже `:ok` (идемпотентно).
  """
  @spec ack(atom()) :: :ok
  def ack(rule), do: GenServer.call(__MODULE__, {:ack, rule})

  @doc "Активные алерты (не подтверждённые)."
  @spec active() :: [alert()]
  def active, do: GenServer.call(__MODULE__, :active)

  @doc "История срабатываний: все правила когда-либо fire'ившие, с статусом."
  @spec history() :: [history_entry()]
  def history, do: GenServer.call(__MODULE__, :history)

  @doc """
  Занести IP в бан-лист на `ms` миллисекунд (перезапись продлевает бан)
  и поднять алерт `:blocked_ip` — дребезг гасит повторяющиеся баны одного
  окна в одно событие. Разбан — `unblock/1` (консоль) или тик по `unblock_at`.
  """
  @spec block_ip(ip(), pos_integer()) :: :ok
  def block_ip(ip, ms), do: GenServer.call(__MODULE__, {:block_ip, ip, ms})

  @doc """
  Забанен ли IP прямо сейчас. Только чтение ETS без GenServer'а — вызывается
  с пути обработки пакетов. Просроченная запись удаляется на месте.
  """
  @spec blocked?(ip()) :: boolean()
  def blocked?(ip) do
    case :ets.lookup(@ban_table, ip) do
      [{^ip, until}] ->
        if until > now() do
          true
        else
          # select_delete, а не delete(ip): удаляем ровно прочитанный объект —
          # если параллельный block_ip уже продлил бан, шаблон не совпадёт
          :ets.select_delete(@ban_table, [{{ip, until}, [], [true]}])
          false
        end

      [] ->
        false
    end
  end

  @doc "Снять IP с бана (команда консоли). Снятие не забаненного IP — `:ok`."
  @spec unblock(ip()) :: :ok
  def unblock(ip), do: GenServer.call(__MODULE__, {:unblock, ip})

  @doc "Активные bans (`until > now`), по возрастанию ip — порядок для консоли."
  @spec blocked_list() :: [ban()]
  def blocked_list do
    now = now()

    @ban_table
    |> :ets.tab2list()
    |> Enum.filter(fn {_ip, until} -> until > now end)
    |> Enum.map(&%{ip: elem(&1, 0), until: elem(&1, 1)})
    |> Enum.sort_by(& &1.ip)
  end

  @impl true
  def init(_opts) do
    @state_table = :ets.new(@state_table, [:set, :protected, :named_table])

    @ban_table =
      :ets.new(@ban_table, [:set, :public, :named_table, read_concurrency: true])

    schedule_tick()
    {:ok, %{}}
  end

  @impl true
  def handle_call({:fire, rule, data}, _from, state) do
    {:reply, trigger(rule, data), state}
  end

  def handle_call({:ack, rule}, _from, state) do
    {:reply, do_ack(rule), state}
  end

  def handle_call({:block_ip, ip, ms}, _from, state) do
    :ets.insert(@ban_table, {ip, now() + ms})
    {:reply, trigger(:blocked_ip, %{ip: ip}), state}
  end

  def handle_call({:unblock, ip}, _from, state) do
    :ets.delete(@ban_table, ip)
    {:reply, :ok, state}
  end

  def handle_call(:active, _from, state) do
    alerts =
      @state_table
      |> :ets.tab2list()
      |> Enum.filter(fn {_rule, entry} -> entry.state == :active end)
      |> Enum.map(&entry/1)
      |> Enum.sort_by(& &1.rule)

    {:reply, alerts, state}
  end

  def handle_call(:history, _from, state) do
    history =
      @state_table
      |> :ets.tab2list()
      |> Enum.map(fn {rule, entry} -> Map.merge(entry, %{rule: rule}) end)
      |> Enum.sort_by(& &1.rule)

    {:reply, history, state}
  end

  # тик: метричные правила по рядам Metrics (ряды — уже посекундные дельты
  # с меткой времени, отдельное дельта-окно в state не нужен) плюс авто-разбан
  @impl true
  def handle_info(:tick, state) do
    now = now()
    snapshot = Metrics.snapshot()
    check_reg_failure(snapshot, now)
    check_tx_timeout_rate(snapshot, now)
    check_retrans_spike(snapshot)
    check_beam_mem()
    sweep_bans(now)
    schedule_tick()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # срабатывание внутри процесса (тик, handle_call) — без рекурсивного call
  defp trigger(rule, data) do
    case :ets.lookup(@state_table, rule) do
      [{^rule, %{state: :active}}] ->
        :ok

      _ ->
        :ets.insert(@state_table, {rule, %{data: data, since: now(), state: :active}})
        PubSub.broadcast(:alert, {:alert_active, rule, data})
        :ok
    end
  end

  defp do_ack(rule) do
    case :ets.lookup(@state_table, rule) do
      [{^rule, entry}] -> :ets.insert(@state_table, {rule, %{entry | state: :acked}})
      [] -> :ok
    end

    :ok
  end

  defp entry({rule, %{data: data, since: since}}), do: %{rule: rule, data: data, since: since}

  # > reg_failure_n отказов REGISTER за reg_failure_window_s
  defp check_reg_failure(snapshot, now) do
    window_ms = rule(:reg_failure_window_s) * 1000

    sum = window_sum(snapshot.series, :reg_fail, window_ms, now)

    if sum > rule(:reg_failure_n), do: trigger(:reg_failure, %{reg_fail: sum})
    :ok
  end

  # > tx_timeout_pct % таймаутов среди завершённых транзакций за окно;
  # tx_started — прокси завершённых: за пределами окна старта ≈ все старта
  # завершились, отдельного счётчика завершений Metrics не ведёт
  defp check_tx_timeout_rate(snapshot, now) do
    window_ms = rule(:tx_timeout_window_s) * 1000
    started = window_sum(snapshot.series, :tx_started, window_ms, now)
    timeouts = window_sum(snapshot.series, :tx_timeout, window_ms, now)

    if started >= @tx_min_completed and timeouts * 100 > rule(:tx_timeout_pct) * started do
      trigger(:tx_timeout_rate, %{started: started, timeouts: timeouts})
    end

    :ok
  end

  # > retrans_per_s ретрансляций в секунду: ряд :retrans — посекундные дельты,
  # свежая точка и есть последняя полная секунда
  defp check_retrans_spike(snapshot) do
    case Map.get(snapshot.series, :retrans, []) |> List.last() do
      {_ts, per_s} ->
        if per_s > rule(:retrans_per_s), do: trigger(:retrans_spike, %{per_s: per_s})

      nil ->
        :ok
    end

    :ok
  end

  defp check_beam_mem do
    total = :erlang.memory(:total)

    if total > rule(:beam_mem_mb) * 1_024 * 1024 do
      trigger(:beam_mem, %{bytes: total})
    end

    :ok
  end

  # авто-разбан по unblock_at; ленивая чистка в blocked?/1 её лишь дополняет
  defp sweep_bans(now) do
    @ban_table
    |> :ets.tab2list()
    |> Enum.each(fn {ip, until} ->
      unless until > now, do: :ets.delete(@ban_table, ip)
    end)
  end

  defp window_sum(series, name, window_ms, now) do
    series
    |> Map.get(name, [])
    |> Enum.reduce(0, fn
      {ts, value}, acc when ts > now - window_ms -> acc + value
      _older, acc -> acc
    end)
  end

  defp rule(key) do
    default = Keyword.fetch!(@default_rules, key)

    case Application.get_env(:sip_pbx, :alert_rules, []) do
      overrides when is_list(overrides) -> Keyword.get(overrides, key, default)
      _ -> default
    end
  end

  defp now, do: System.system_time(:millisecond)

  defp schedule_tick, do: Process.send_after(self(), :tick, @tick_ms)
end
