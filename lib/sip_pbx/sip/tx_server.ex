defmodule SipPbx.SIP.TxServer do
  @moduledoc """
  Серверная транзакция RFC 3261 §17.2 (IST для INVITE, NIST для прочих):
  заводится роутером на новый запрос, регистрирует в `SipPbx.SIP.Transport`
  ОБА ключа — `{:srv, branch, метод, cseq, from}` (дубликаты запроса) и
  `{:srv, branch, "ACK:" <> метод, cseq, from}` (ACK к последнему ответу,
  метод берётся из CSeq — правило Task 7) — и сама раздаёт ответы: дубликат
  запроса получает авто-ретранслят последнего ответа, ACK в completed гасит
  транзакцию (`{:tx_acked, ref}` владельцу).

  Автомат trying→proceeding→completed (INVITE) / trying→completed (NIST).
  IST в completed ретранслирует final по Timer G (шаг `T1·2^n`, потолок T2) до
  дедлайна Timer H = 64·T1 — там `{:tx_timeout_owner, ref}` и гибель; NIST не
  ретранслирует по таймеру вовсе (только по дубликатам запроса), живёт те же
  64·T1 (Timer D в упрощении плана) и на истечении D умирает молча: финал
  отправлял сам владелец, считать это таймаутом — плодить ложные
  `tx_timeout_rate`. Процесс ephemeral (`:temporary`), живёт под
  `SipPbx.SIP.TransactionSupervisor`. Константы — только из env `:t1_ms`.
  """

  use GenServer, restart: :temporary

  alias SipPbx.Metrics
  alias SipPbx.SIP.{Message, Transport}

  @typedoc "Плечо транзакции: INVITE-серверная (IST) или прочая серверная (NIST)."
  @type kind :: :invite | :other

  @typedoc "Различитель транзакции для владельца: `{branch, метод, cseq}`."
  @type ref :: {String.t() | nil, String.t() | nil, non_neg_integer() | nil}

  @enforce_keys [:transport, :owner, :ref, :kind, :from, :msg, :req_key, :ack_key]
  defstruct [
    :transport,
    :owner,
    :ref,
    :kind,
    :from,
    :msg,
    # ключ дубликата запроса и ACK-ключ (снимаем оба в terminate)
    :req_key,
    :ack_key,
    # последний отправленный ответ — авто-ретранслят на дубликаты и Timer G
    last_resp: nil,
    t1: 0,
    t2: 0,
    # абсолютный дедлайн (monotonic, мс) — таймеры H/D
    deadline: 0,
    # автомат: :trying | :proceeding | :completed
    st: :trying,
    # текущий шаг Timer G, мс
    step: 0,
    # ref последнего Process.send_after (:retrans)
    timer: nil,
    # ключи уже сняты до выхода (terminate — страховка только для внешних
    # stop/kill); письмо владельцу из terminate, процесс уже exiting —
    # получатель не застанет транзакцию живой (гонка refute Process.alive?/1)
    cleaned: false,
    # что послать владельцу в terminate (:tx_acked/:tx_timeout_owner по ref);
    # nil — тихий выход (NIST по D, внешний stop)
    notify: nil,
    # поколение цепочки тиков: устаревшие {:retrans, gen} игнорируются
    # (cancel_timer не закрывает гонку «тик уже извлечён», как в TxClient)
    gen: 0
  ]

  @doc """
  Запустить серверную транзакцию по принятому запросу: `:transport` — экземпляр
  `Transport`, `:owner` — кому достанутся `{:tx_acked, ref}` и
  `{:tx_timeout_owner, ref}`, `:kind` — `:invite | :other`, `:msg` — запрос,
  `:from` — UDP-пир отправителя (ему и шлём ответы). Ключи выводятся из msg
  (branch/CSeq) и `from`, оба реестрируются сразу — до первого ответа.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Послать 100 Trying (ответ собирает транзакция из запроса). Вызов синхронный:
  когда вернулся `:ok`, 100 уже в сокете транспорта.
  """
  @spec trying(GenServer.server()) :: :ok
  def trying(tx), do: GenServer.call(tx, :trying)

  @doc """
  Отправить готовый ответ (собирает вызывающий — Registrar/Proxy — со всеми
  заголовками): `final? = false` — 1xx, транзакция в Proceeding; `final? = true`
  — финал, переход в Completed со всеми ретранслятами. Ответ в Completed больше
  не меняется (повторный вызов игнорируется).

  2xx завершает диалог, а не транзакцию: держим её до ACK/D штатно, но
  сделавшему своё владельцу (Registrar после 200 OK, Proxy после форварда ACK)
  ждать 64·T1 рано — ранний выход: `stop/1` (или
  `DynamicSupervisor.terminate_child(TransactionSupervisor, tx)`).
  """
  @spec respond(GenServer.server(), Message.t(), boolean()) :: :ok
  def respond(tx, %Message{} = response, final?),
    do: GenServer.call(tx, {:respond, response, final?})

  @doc """
  Погасить транзакцию досрочно (сделали своё после финального ответа —
  выжидать Timer D/hold для ACK смысла нет). Ключи реестра снимает terminate.
  """
  @spec stop(GenServer.server()) :: :ok
  def stop(tx), do: GenServer.stop(tx)

  @impl true
  def init(opts) do
    t1 = Application.fetch_env!(:sip_pbx, :t1_ms)
    msg = Keyword.fetch!(opts, :msg)
    from = Keyword.fetch!(opts, :from)
    branch = Message.branch(msg)

    # ключ дубликата совпадает с Transport.srv_key для non-ACK-запроса:
    # метод из start-строки; ACK-ключ — «ACK:» + метод из CSeq (Transport для
    # ACK собирает его так же); мусорный CSeq даёт {nil, nil} — ключ «ACK:»
    # тогда ни с чем не матчится, это ожидаемо (review Task 2)
    {cseq_num, cseq_method} =
      case Message.cseq(msg) do
        {n, m} -> {n, m}
        nil -> {nil, nil}
      end

    req_key = {:srv, branch, msg.method, cseq_num, from}
    ack_method = if is_binary(cseq_method), do: "ACK:" <> cseq_method, else: "ACK:"
    ack_key = {:srv, branch, ack_method, cseq_num, from}

    state = %__MODULE__{
      transport: Keyword.get(opts, :transport, Transport),
      owner: Keyword.fetch!(opts, :owner),
      ref: {branch, msg.method, cseq_num},
      kind: Keyword.fetch!(opts, :kind),
      from: from,
      msg: msg,
      req_key: req_key,
      ack_key: ack_key,
      t1: t1,
      t2: 8 * t1
    }

    # monitor транспорта снимет ключи, если мы умрём; reg_tx отвечает :ok
    :ok = Transport.reg_tx(state.transport, req_key, self(), :srv)
    :ok = Transport.reg_tx(state.transport, ack_key, self(), :srv)
    Metrics.incr(:tx_started)
    {:ok, state}
  end

  # 100 Trying — только из Trying; ответ собирается из запроса (все Via,
  # From/To/Call-ID/CSeq копиями), §17.2.1
  @impl true
  def handle_call(:trying, _from, %{st: :trying} = state) do
    resp = trying_response(state.msg)
    send_response(state, resp)
    {:reply, :ok, %{state | last_resp: resp}}
  end

  def handle_call(:trying, _from, state), do: {:reply, :ok, state}

  # финальный ответ в Completed не принимаем: IST уже крутит Timer G со своим
  # last_resp, подмена ответа сломала бы инвариант «final ретранслируется как есть»
  def handle_call({:respond, _resp, _final?}, _from, %{st: :completed} = state),
    do: {:reply, :ok, state}

  def handle_call({:respond, resp, final?}, _from, state) do
    send_response(state, resp)
    state = %{state | last_resp: resp}

    if final? do
      {:reply, :ok, enter_completed(state)}
    else
      {:reply, :ok, %{state | st: :proceeding}}
    end
  end

  # §17.2.1: тик IST — ретранслят final (Timer G, шаг T1·2^n с потолком T2)
  # до дедлайна H = 64·T1, там уведомление владельцу и гибель
  @impl true
  def handle_info({:retrans, gen}, %{st: :completed, kind: :invite, gen: gen} = state) do
    if expired?(state) do
      timeout(state)
    else
      Metrics.incr(:retrans)
      send_response(state, state.last_resp)
      step = min(state.step * 2, state.t2)
      {:noreply, %{state | step: step, timer: schedule_tick(gen, step)}}
    end
  end

  # §17.2.2: тик NIST стоит ровно один раз на дедлайне D = 64·T1 (ретранслят —
  # исключительно по дубликатам запроса). D истёк — тихая гибель: финальный
  # ответ отправлял сам владелец, {:tx_timeout_owner} здесь был бы шумом,
  # а :tx_timeout на каждом живом 200 OK ложно поднимал tx_timeout_rate
  def handle_info({:retrans, gen}, %{st: :completed, kind: :other, gen: gen} = state) do
    if expired?(state) do
      {:stop, :normal, state}
    else
      # проспал дедлайн на наносекунды — переставляемся на остаток
      {:noreply, %{state | timer: schedule_tick(gen, remaining(state))}}
    end
  end

  # тик заменённой цепочки — молча мимо (gen-схема как в TxClient)
  def handle_info({:retrans, _stale_gen}, state), do: {:noreply, state}

  # ACK из Transport (приходит как {:tx_dup, ...} по ACK-ключу). §17.2.1:
  # доставка тушке обязательна и вне Completed (ACK может обогнать final —
  # гонка ретранслятов; Proxy T13 по {:tx_acked, ref} ре-форвардит ACK).
  # В Completed ACK дополнительно гасит транзакцию; Timer I/Confirmed с
  # выдержкой в упрощении не заводим (ACK по branch надёжно матчуется
  # вторым ключом)
  @impl true
  def handle_info({:tx_dup, %Message{method: "ACK"}, _from}, %{st: :completed} = state) do
    state = cleanup_keys(state)
    {:stop, :normal, %{state | notify: {:tx_acked, state.ref}}}
  end

  def handle_info({:tx_dup, %Message{method: "ACK"}, _from}, state) do
    send(state.owner, {:tx_acked, state.ref})
    {:noreply, state}
  end

  # дубликат запроса: авто-ретранслят последнего ответа (Trying — повтор 100,
  # Proceeding — последнего 1xx, Completed — final), §17.2.1/§17.2.2 и
  # регрессия ECSS-10 «повтор 100/180, никогда 486». До первого ответа — тишина.
  # Цепочку Timer G не перезапускаем: у IST она уже идёт, NIST по таймеру не
  # ретранслирует вовсе (упрощение плана, §17.2.2 допускает рестарт G).
  def handle_info({:tx_dup, _msg, _from}, state) do
    if state.last_resp do
      Metrics.incr(:retrans)
      send_response(state, state.last_resp)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Уведомление — здесь, не в handle_info: к моменту, когда владелец читает
  # {:tx_acked, ref}/{:tx_timeout_owner, ref}, процесс уже exiting — никаких
  # «живой транзакции» под assert'ами. Снятие ключей — только для нештатных
  # выходов (внешний stop/kill): штатные сняли до stop; в окно перезапуска
  # транспорта не роняемся (carry из ревью T8), monitor транспорта — страховка
  @impl true
  def terminate(_reason, state) do
    unless state.cleaned, do: unreg_keys(state)
    if state.notify, do: send(state.owner, state.notify)
    :ok
  catch
    :exit, _ -> :ok
  end

  defp cleanup_keys(state) do
    unreg_keys(state)
    %{state | cleaned: true}
  catch
    :exit, _ -> %{state | cleaned: true}
  end

  defp unreg_keys(state) do
    :ok = Transport.unreg_tx(state.transport, state.req_key)
    :ok = Transport.unreg_tx(state.transport, state.ack_key)
  end

  defp enter_completed(%{kind: :invite, gen: gen} = state) do
    # Timer G: первый ретранслят через T1, шаг удваивается до T2; дедлайн H
    # отсчитывается от отправки final
    %{
      state
      | st: :completed,
        deadline: System.monotonic_time(:millisecond) + 64 * state.t1,
        step: state.t1,
        gen: gen + 1,
        timer: schedule_tick(gen + 1, state.t1)
    }
  end

  defp enter_completed(%{kind: :other, gen: gen} = state) do
    # NIST: тик ровно на дедлайне D = 64·T1, ретранслят только по дубликатам
    %{
      state
      | st: :completed,
        deadline: System.monotonic_time(:millisecond) + 64 * state.t1,
        gen: gen + 1,
        timer: schedule_tick(gen + 1, 64 * state.t1)
    }
  end

  defp trying_response(req) do
    base = %Message{type: :response, status_code: 100, reason: "Trying"}

    resp =
      Enum.reduce(Message.headers(req, "via"), base, &Message.append_header(&2, "via", &1))

    resp =
      Enum.reduce(["from", "to", "call-id", "cseq"], resp, fn name, acc ->
        case Message.header(req, name) do
          nil -> acc
          value -> Message.append_header(acc, name, value)
        end
      end)

    Message.put_header(resp, "content-length", "0")
  end

  defp send_response(state, resp),
    do: Transport.send_msg(state.transport, state.from, Message.to_iodata(resp))

  defp expired?(state), do: System.monotonic_time(:millisecond) >= state.deadline

  defp remaining(state),
    do: max(state.deadline - System.monotonic_time(:millisecond), 1)

  defp timeout(state) do
    Metrics.incr(:tx_timeout)
    state = cleanup_keys(state)
    {:stop, :normal, %{state | notify: {:tx_timeout_owner, state.ref}}}
  end

  defp schedule_tick(gen, ms), do: Process.send_after(self(), {:retrans, gen}, ms)
end
