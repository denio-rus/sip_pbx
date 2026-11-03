defmodule SipPbx.LogBuffer do
  @moduledoc """
  Кольцевой SIP-журнал: последняя `capacity` (боевая 2000) записей в ETS
  `:ordered_set` по монотонному SEQ. `add/3` — cast без ожидания ответа
  (горячий путь транспорта), `all/0` — синхронный вызов, чтобы читатель видел
  уже принятые записи. Запись: `%{dir: :in | :out | :info, first:, raw:, ts:}`.
  """

  use GenServer

  @table __MODULE__
  @default_capacity 2000
  # индексы :atomics: 1 — выданный SEQ, 2 — число записей в таблице
  @seq_ix 1
  @len_ix 2

  @type dir :: :in | :out | :info
  @type entry :: %{dir: dir(), first: String.t(), raw: String.t(), ts: integer()}

  @doc """
  Запустить журнал; `:capacity` — размер кольца (по умолчанию #{@default_capacity}).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Допisać запись в журнал, не дожидаясь ответа процесса. `first` — первая
  строка пакета (или произвольная строка для `:info`).
  """
  @spec add(dir(), String.t(), String.t()) :: :ok
  def add(dir, first, raw) do
    GenServer.cast(__MODULE__, {:add, dir, first, raw})
  end

  @doc "Все записи от старых к новым."
  @spec all() :: [entry()]
  def all, do: GenServer.call(__MODULE__, :all)

  @impl true
  def init(opts) do
    capacity = Keyword.get(opts, :capacity, @default_capacity)
    table = :ets.new(@table, [:ordered_set, :public, :named_table, read_concurrency: true])
    counters = :atomics.new(2, signed: false)
    {:ok, %{table: table, capacity: capacity, counters: counters, low: 1}}
  end

  @impl true
  def handle_cast({:add, dir, first, raw}, state) do
    seq = :atomics.add_get(state.counters, @seq_ix, 1)
    len = :atomics.add_get(state.counters, @len_ix, 1)
    entry = %{dir: dir, first: first, raw: raw, ts: System.system_time(:millisecond)}
    :ets.insert(state.table, {seq, entry})
    {:noreply, trim(len, state)}
  end

  @impl true
  def handle_call(:all, _from, state) do
    entries =
      state.table
      |> :ets.tab2list()
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(&elem(&1, 1))

    {:reply, entries, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # SEQ плотный, начинается с 1 — старейшая запись всегда стоит по ключу low
  defp trim(len, %{capacity: capacity} = state) when len > capacity do
    :ets.delete(state.table, state.low)
    :atomics.sub(state.counters, @len_ix, 1)
    trim(len - 1, %{state | low: state.low + 1})
  end

  defp trim(_len, state), do: state
end
