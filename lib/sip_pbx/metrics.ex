defmodule SipPbx.Metrics do
  @moduledoc """
  Счётчики и временные ряды АТС: map-счётчики в GenServer (инкремент — cast),
  раз в секунду сэмплер снимает дельты счётчиков и значения гейджей в
  ETS-кольца `:sip_pbx_series` (по 3600 точек на метрику).

  ## Счётчики (источник имён)

  * `:pkt_in`, `:pkt_out` — принятые/отправленные UDP-пакеты;
  * `:pkt_dup` — дубликаты (retransmission detected);
  * `:pkt_dropped_banned` — брошено по бан-листу;
  * `:parse_fail` — ошибки парсинга SIP;
  * `:reg_ok`, `:reg_fail` — итоги REGISTER;
  * `:auth_fail` — digest-проверка не пройдена;
  * `:tx_started`, `:tx_timeout` — транзакции начаты/истекли;
  * `:retrans` — отправлено ретрансляций;
  * `:call_started`, `:call_ok`, `:call_fail` — исходящие вызовы;
  * `:call_active` — подтверждён ACK'ом (диалог жив);
  * `:bye_done`, `:cancel_done` — завершены по BYE / CANCEL;
  * `:tx_503` — отказ по лимиту живых транзакций (`:max_tx`).

  Коды ответов в счётчики не заводятся (ruling T13): детализация по кодам —
  в журнале `SipPbx.LogBuffer`, здесь только итоговые имена выше.
  """

  use GenServer

  @series :sip_pbx_series
  @series_len 3600
  @tick_ms 1000

  @type sample :: {integer(), number()}
  @type snapshot :: %{
          counters: %{optional(atom()) => non_neg_integer()},
          series: %{optional(atom()) => [sample()]}
        }

  defstruct counters: %{}, gauges: %{}, last: %{}

  @doc """
  Запустить хранилище метрик и сэмплер (тик 1000 мс).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Увеличить счётчик на `n` (по умолчанию 1), не дожидаясь ответа."
  @spec incr(atom(), pos_integer()) :: :ok
  def incr(name, n \\ 1), do: GenServer.cast(__MODULE__, {:incr, name, n})

  @doc "Текущее значение счётчика (неизвестное имя — 0)."
  @spec get(atom()) :: non_neg_integer()
  def get(name), do: GenServer.call(__MODULE__, {:get, name})

  @doc """
  Зарегистрировать гейдж — функцию `() -> number`, которую сэмплер опрашивает
  каждый тик (например, глубину очереди или активные вызовы). Если замыкание
  падает, сэмпл этого тика пропускается — сэмплер не роняется.
  """
  @spec gauge(atom(), (-> number())) :: :ok
  def gauge(name, fun), do: GenServer.call(__MODULE__, {:gauge, name, fun})

  @doc """
  Снимок: накопленные счётчики и ряды `[{ts_ms, value}]` от старых к новым.
  """
  @spec snapshot() :: snapshot()
  def snapshot, do: GenServer.call(__MODULE__, :snapshot)

  @impl true
  def init(_opts) do
    @series =
      :ets.new(@series, [:ordered_set, :public, :named_table, read_concurrency: true])

    schedule_tick()
    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_cast({:incr, name, n}, state) do
    {:noreply, %{state | counters: Map.update(state.counters, name, n, &(&1 + n))}}
  end

  @impl true
  def handle_call({:get, name}, _from, state) do
    {:reply, Map.get(state.counters, name, 0), state}
  end

  def handle_call({:gauge, name, fun}, _from, state) do
    {:reply, :ok, %{state | gauges: Map.put(state.gauges, name, fun)}}
  end

  def handle_call(:snapshot, _from, state) do
    series =
      @series
      |> :ets.tab2list()
      |> Enum.reduce(%{}, fn {{name, ts}, value}, acc ->
        Map.update(acc, name, [{ts, value}], &[{ts, value} | &1])
      end)
      |> Enum.map(fn {name, samples} -> {name, Enum.reverse(samples)} end)
      |> Map.new()

    {:reply, %{counters: state.counters, series: series}, state}
  end

  @impl true
  def handle_info(:tick, state) do
    now = System.system_time(:millisecond)

    names =
      Enum.map(state.counters, fn {name, value} ->
        put_sample(name, now, value - Map.get(state.last, name, 0))
        name
      end) ++
        Enum.map(state.gauges, fn {name, fun} ->
          put_gauge_sample(name, now, fun)
          name
        end)

    Enum.each(names, &trim_series/1)
    schedule_tick()
    {:noreply, %{state | last: state.counters}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  defp put_sample(name, ts, value), do: :ets.insert(@series, {{name, ts}, value})

  # Замыкания гейджей исполняются в процессе Metrics и в будущих задачах будут
  # трогать другие процессы (например, GenServer.call на мёртвый pid) — ронять
  # из-за них сэмплер вместе со всеми счётчиками нельзя, поэтому при падении
  # просто пропускаем сэмпл этого тика.
  defp put_gauge_sample(name, ts, fun) do
    put_sample(name, ts, fun.())
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # кольцо на метрику: ключ {name, ts}, старее последних @series_len выбрасываем
  defp trim_series(name) do
    @series
    |> :ets.match({{name, :"$1"}, :_})
    |> Enum.map(&hd/1)
    |> Enum.sort(:desc)
    |> Enum.drop(@series_len)
    |> Enum.each(&:ets.delete(@series, {name, &1}))
  end

  defp schedule_tick, do: Process.send_after(self(), :tick, @tick_ms)
end
