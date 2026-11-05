defmodule SipPbx.CallTracker do
  # константы до @moduledoc: он их интерполирует
  @ring 500

  @moduledoc """
  Трассировка вызовов: лента состояний каждого плеча (A/B) на вызов и кольцо
  последних #{@ring} завершённых — для консоли (Task 14) и отладки Proxy
  (Task 13). Каждый переход плеча рассылает `{:call_state, call_id, leg, state}`
  в топик `:call_event` `SipPbx.PubSub`.

  Хранение — ETS `:public` `:sip_pbx_calls` (ключ `call_id`), как бан-лист
  `SipPbx.Alerts`: `list/0` и `get/1` читают напрямую без GenServer'а. Писатель
  один — процесс ниже: `begin/3` и `set_state/4` идут cast'ами, `finish/3` —
  call, чтобы запись точно лежала в таблице к моменту возврата (чтение сразу
  после finish не гонит). Порядок в `list/0` — по monotonic-метке вставки в
  значении, а не по временным меткам плеч: caller может передать абсолютные
  метки (тесты — нулевые), кольцо на них опираться не должно.
  """

  use GenServer

  alias SipPbx.PubSub

  @table :sip_pbx_calls

  @typedoc "Лег трассировки: имя плеча и лента переходов `%{state => метка времени caller'а}`."
  @type leg_timeline :: %{name: leg_name(), states: %{optional(atom()) => integer()}}

  @typedoc "Плечо вызова: `:a` — инициатор, `:b` — отвечающая сторона."
  @type leg_name :: :a | :b

  @typedoc "Статус вызова: `:progress` пока не завершён, дальше — итог `finish/3`."
  @type status :: :progress | :answered | :canceled | :failed | :hangup

  @typedoc "Строка трассировки: участники, итог, длительность и ленты плеч."
  @type row :: %{
          call_id: String.t(),
          caller: String.t(),
          callee: String.t(),
          status: status(),
          code: integer() | nil,
          duration_ms: integer() | nil,
          legs: [leg_timeline()],
          # monotonic-метка вставки — только порядок кольца, внешнего смысла нет
          ts: integer(),
          started_at: integer()
        }

  @doc """
  Запустить трассировщик: создать ETS-таблицу `:sip_pbx_calls` (`:public`,
  ключ `call_id`).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Начать трассировку вызова: обе ленты плеч пустые, статус `:progress`.
  Повторный `begin/3` того же `call_id` перезаписывает строку (новый вызов с
  новым Call-ID — нормальный путь, коллизий не ожидается).
  """
  @spec begin(String.t(), String.t(), String.t()) :: :ok
  def begin(call_id, caller, callee) do
    GenServer.cast(__MODULE__, {:begin, call_id, caller, callee})
  end

  @doc """
  Переход плеча `leg` в состояние `state` с меткой `now_ms` (по умолчанию —
  текущее время): в ленту плеча (повтор перехода в то же состояние перетирает
  метку) и broadcast `{:call_state, call_id, leg, state}` в `:call_event`.
  Неизвестный `call_id` (завершён и вытеснен кольцом) — молча `:ok`.
  """
  @spec set_state(String.t(), leg_name(), atom(), integer()) :: :ok
  def set_state(call_id, leg, state, now_ms \\ now()) do
    GenServer.cast(__MODULE__, {:set_state, call_id, leg, state, now_ms})
  end

  @doc """
  Завершить вызов: итог `status` с кодом ответа `code` (`nil` — без кода),
  `duration_ms` от `begin/3` до текущего момента. Call — чтобы `list/0` видел
  финал сразу после возврата. Завершение неизвестного `call_id` — `:ok`.
  """
  @spec finish(String.t(), :answered | :canceled | :failed | :hangup, integer() | nil) :: :ok
  def finish(call_id, status, code) do
    GenServer.call(__MODULE__, {:finish, call_id, status, code})
  end

  @doc "Все строки трассировки, новые сверху (по метке вставки)."
  @spec list() :: [row()]
  def list do
    @table
    |> :ets.tab2list()
    |> Enum.map(fn {_call_id, row} -> row end)
    |> Enum.sort_by(& &1.ts, :desc)
  end

  @doc "Строка трассировки вызова либо `nil`."
  @spec get(String.t()) :: row() | nil
  def get(call_id) do
    case :ets.lookup(@table, call_id) do
      [{^call_id, row}] -> row
      [] -> nil
    end
  end

  @impl true
  def init(_opts) do
    @table = :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:begin, call_id, caller, callee}, state) do
    row = %{
      call_id: call_id,
      caller: caller,
      callee: callee,
      status: :progress,
      code: nil,
      duration_ms: nil,
      legs: [%{name: :a, states: %{}}, %{name: :b, states: %{}}],
      ts: System.monotonic_time(:millisecond),
      started_at: now()
    }

    :ets.insert(@table, {call_id, row})
    trim_ring()
    {:noreply, state}
  end

  def handle_cast({:set_state, call_id, leg, state_name, now_ms}, state) do
    case :ets.lookup(@table, call_id) do
      [{^call_id, row}] ->
        :ets.insert(@table, {call_id, put_leg_state(row, leg, state_name, now_ms)})
        PubSub.broadcast(:call_event, {:call_state, call_id, leg, state_name})

      [] ->
        :ok
    end

    {:noreply, state}
  end

  @impl true
  def handle_call({:finish, call_id, status, code}, _from, state) do
    case :ets.lookup(@table, call_id) do
      [{^call_id, row}] ->
        finished = %{
          row
          | status: status,
            code: code,
            duration_ms: now() - row.started_at
        }

        :ets.insert(@table, {call_id, finished})

      [] ->
        :ok
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  defp put_leg_state(row, leg, state_name, now_ms) do
    legs =
      Enum.map(row.legs, fn
        %{name: ^leg} = l -> %{l | states: Map.put(l.states, state_name, now_ms)}
        other -> other
      end)

    %{row | legs: legs}
  end

  # кольцо: сверх @ring записей при вставке уходит самая старая по monotonic
  # метке; записей ≤ @ring + 1, линейный поиск минимума дешевле упорядоченной
  # таблицы, которая ломала бы чтение по ключу
  defp trim_ring do
    if :ets.info(@table, :size) > @ring do
      {oldest_id, _row} =
        @table
        |> :ets.tab2list()
        |> Enum.min_by(fn {_id, row} -> row.ts end)

      :ets.delete(@table, oldest_id)
    end

    :ok
  end

  defp now, do: System.system_time(:millisecond)
end
