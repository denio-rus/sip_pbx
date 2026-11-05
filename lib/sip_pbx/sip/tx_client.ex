defmodule SipPbx.SIP.TxClient do
  @moduledoc """
  Клиентская транзакция RFC 3261 §17.1: отправляет запрос, регистрирует ключ
  `{:cli, branch}` в `SipPbx.SIP.Transport` и сама ретранслирует по таймеру A/E
  (шаг `min(T1·2^n, T2)`), пока не придёт ответ или не истечёт таймер B/F
  (64·T1) — тогда владельцу `{:tx_timeout, ref}` и гибель. Финальный ответ
  (кроме 2xx на INVITE — их Transport несёт роутеру, §17.1.1.3) уходит владельцу
  как `{:tx_resp, ref, msg}`, а транзакция входит в Completed: ретранслирует
  запрос каждые T2, пока владелец не пошлёт ACK и не погасит `stop/1`
  (INVITE) или `stop/1` после дела (прочие). INVITE после 1xx не ретранслируется
  вовсе — остаётся только дедлайн Timer M (тот же 64·T1).

  Константы только из env `:t1_ms` (T2 = 8·T1, дедлайн = 64·T1); в тестовом
  окружении T1 = 20 мс, чтобы гонять автоматы миллисекундами. Процесс —
  ephemeral-GenServer (`:temporary`), под `TransactionSupervisor` (Task 9).
  """

  use GenServer, restart: :temporary

  alias SipPbx.Metrics
  alias SipPbx.SIP.{Message, Transport}

  @typedoc "Плечо транзакции: INVITE-клиентская или прочая клиентская."
  @type kind :: :invite | :other

  @enforce_keys [:transport, :owner, :ref, :kind, :target, :msg, :branch]
  defstruct transport: nil,
            owner: nil,
            ref: nil,
            kind: :other,
            target: nil,
            msg: nil,
            branch: nil,
            t1: 0,
            t2: 0,
            # абсолютный дедлайн (monotonic, мс) — таймеры B/F/M
            deadline: 0,
            # автомат: :trying | :proceeding | :completed
            st: :trying,
            # текущий шаг ретранслята, мс
            step: 0,
            # ref последнего Process.send_after (:retrans) — гасится при смене фазы
            timer: nil

  @doc """
  Запустить транзакцию и сразу отправить запрос: `:transport` — экземпляр
  `Transport`, `:owner` — кому достанутся `{:tx_resp, ref, msg}` и
  `{:tx_timeout, ref}`, `:ref` — термин различения (Proxy берёт
  `{:b|:n|:c, call_id}`), `:kind` — `:invite | :other`, `:target` — UDP-пир,
  `:msg` — готовый запрос (branch берётся из его верхнего Via).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Погасить транзакцию владельцу (получил 2xx / послал ACK / сделал своё)."
  @spec stop(GenServer.server()) :: :ok
  def stop(tx), do: GenServer.stop(tx)

  @impl true
  def init(opts) do
    t1 = Application.fetch_env!(:sip_pbx, :t1_ms)
    msg = Keyword.fetch!(opts, :msg)
    branch = Message.branch(msg)

    state = %__MODULE__{
      transport: Keyword.get(opts, :transport, Transport),
      owner: Keyword.fetch!(opts, :owner),
      ref: Keyword.fetch!(opts, :ref),
      kind: Keyword.fetch!(opts, :kind),
      target: Keyword.fetch!(opts, :target),
      msg: msg,
      branch: branch,
      t1: t1,
      t2: 8 * t1,
      deadline: System.monotonic_time(:millisecond) + 64 * t1,
      step: t1
    }

    # reg_tx отвечает :ok; monitor транспорта снимет ключ, если мы умрём
    :ok = Transport.reg_tx(state.transport, {:cli, branch}, self(), tx_kind(state.kind))
    Metrics.incr(:tx_started)
    send_request(state)
    {:ok, %{state | timer: schedule_tick(t1)}}
  end

  # §17.1.2: один тик — либо ретранслят с удвоением шага, либо дедлайн B/F/M.
  # В Completed шаг фиксирован (T2), в Proceeding для INVITE — тик только
  # про дедлайн (Timer M), без ретранслята.
  @impl true
  def handle_info(:retrans, %{st: :proceeding, kind: :invite} = state) do
    if expired?(state) do
      timeout(state)
    else
      # Proceeding без ретранслята: тик остаётся только сторожем дедлайна
      {:noreply, %{state | timer: schedule_tick(state.t2)}}
    end
  end

  def handle_info(:retrans, state) do
    if expired?(state) do
      timeout(state)
    else
      Metrics.incr(:retrans)
      send_request(state)
      step = if state.st == :completed, do: state.t2, else: min(state.step * 2, state.t2)
      {:noreply, %{state | step: step, timer: schedule_tick(step)}}
    end
  end

  # ответ от Transport'а (кроме 2xx на INVITE — их он уводит роутеру)

  # §17.1.2.2: в Completed ответы не обрабатываются — ретрансляты финального
  # ответа и опоздавшие 1xx от UAS не должны вторично будить владельца
  @impl true
  def handle_info({:tx_resp, _msg, _from}, %{st: :completed} = state), do: {:noreply, state}

  @impl true
  def handle_info({:tx_resp, msg, _from}, state) do
    send(state.owner, {:tx_resp, state.ref, msg})

    if msg.status_code < 200 do
      # 1xx: ICT переходит на Timer M (ретранслят выключен), NICT гоняет A/E дальше
      {:noreply, %{state | st: :proceeding}}
    else
      # финал: Completed, ретранслят запроса каждые T2 до stop (Timer E/F);
      # младый тик A/B гасится, иначе с T2-тика набегают двойные ретрансляты
      cancel_tick(state)
      {:noreply, %{state | st: :completed, step: state.t2, timer: schedule_tick(state.t2)}}
    end
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    # ключ всё равно вычистит monitor Transport'а по нашей смерти, но здесь
    # освобождение немедленное; в окно перезапуска транспорта не роняемся
    Transport.unreg_tx(state.transport, {:cli, state.branch})
  catch
    :exit, _ -> :ok
  end

  defp tx_kind(:invite), do: :cli_invite
  defp tx_kind(:other), do: :cli_other

  defp send_request(state),
    do: Transport.send_msg(state.transport, state.target, Message.to_iodata(state.msg))

  defp expired?(state), do: System.monotonic_time(:millisecond) >= state.deadline

  defp timeout(state) do
    Metrics.incr(:tx_timeout)
    send(state.owner, {:tx_timeout, state.ref})
    {:stop, :normal, state}
  end

  defp schedule_tick(ms), do: Process.send_after(self(), :retrans, ms)

  defp cancel_tick(%{timer: ref}) when is_reference(ref), do: Process.cancel_timer(ref)
  defp cancel_tick(_state), do: :ok
end
