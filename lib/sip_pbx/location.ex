defmodule SipPbx.Location do
  @moduledoc """
  Реестр bindings зарегистрированных абонентов: AOR → Contact с received-адресом
  и абсолютным expiry. Писатель — Registrar (Task 11), читатель — Proxy (Task 13)
  при маршрутизации INVITE.

  Хранение — ETS `:public`: `lookup/2` и `list/1` читают напрямую, без GenServer'а;
  все записи сериализуются через процесс. Sweep раз в 10 с снимает истёкшие,
  истёкший binding лениво удаляется и при `lookup/2` — ровно прочитанный объект
  (`select_delete`), чтобы читатель не затёр свежего конкурента.
  """

  use GenServer

  @table __MODULE__
  @sweep_ms 10_000

  # аналог inet:ip_address()/inet:port_number(): Elixir не резолвит удалённые
  # типы Erlang-модулей в spec'ах, поэтому кортежи расписаны явно
  @type ip ::
          {0..255, 0..255, 0..255, 0..255}
          | {0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535,
             0..65_535}
  @type received :: {ip(), 0..65_535}

  @typedoc """
  Binding из REGISTER: сырой Contact, адрес из него, observed-адрес пакета
  (`{ip, port}`), приоритет `q` и абсолютный момент истечения в мс.
  """
  @type binding :: %{
          contact: String.t(),
          uri: String.t(),
          received: received(),
          q: number(),
          expires_at: integer()
        }

  @doc """
  Запустить реестр: создать ETS-таблицу `#{inspect(__MODULE__)}` и завести
  sweep истёкших bindings каждые #{@sweep_ms} мс.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Записать binding для AOR — один binding на AOR: повторный REGISTER
  перезаписывает binding безусловно, побеждает последний по порядку приёма
  (спека §5; порядок задаёт сериализация записей через процесс). `now_ms` —
  метка времени вызывающего, в записи не участвует: при last-wins порядок
  REGISTER'ов важнее меток, а retransmit того же REGISTER перезаписывает
  binding тем же содержимым.

  Это `call`, а не cast: читатель обязан видеть binding сразу после того, как
  Registrar получил `:ok` (иначе тесты и `POST /api/command` читают гонку).
  """
  @spec register(String.t(), binding(), integer()) :: :ok
  def register(aor, %{} = binding, _now_ms) do
    GenServer.call(__MODULE__, {:register, aor, binding})
  end

  @doc """
  Активный binding AOR на момент `now_ms` (по умолчанию — текущее время),
  `nil` если абонент не зарегистрирован. Истёкший binding — `nil`, запись
  при этом удаляется (ленивая чистка, sweep её лишь дополняет).
  """
  @spec lookup(String.t(), integer()) :: binding() | nil
  def lookup(aor, now_ms \\ now()) do
    case :ets.lookup(@table, aor) do
      [{^aor, b}] ->
        if live?(b, now_ms) do
          b
        else
          # select_delete, а не delete(aor): удаляем ровно прочитанный объект —
          # если до удаления через GenServer успел закоммититься register того
          # же AOR, шаблон не совпадёт и свежий binding переживёт чистку
          :ets.select_delete(@table, [{{aor, b}, [], [true]}])
          nil
        end

      [] ->
        nil
    end
  end

  @doc "Снять AOR с регистрации (REGISTER с `Expires: 0`)."
  @spec unregister(String.t()) :: :ok
  def unregister(aor) do
    GenServer.call(__MODULE__, {:drop_aors, [aor]})
  end

  @doc """
  Команда консоли «снять абонента»: удаляет все bindings AOR вида
  `sip:<номер>@…`. AOR собирается из хоста Request-URI, а не из config-`realm`,
  поэтому ищем по префиксу номера до `@`, а не по одному каноническому AOR.
  Возвращает число снятых записей.
  """
  @spec drop_number(String.t()) :: non_neg_integer()
  def drop_number(number), do: GenServer.call(__MODULE__, {:drop_number, number})

  @doc "Все активные на `now_ms` bindings как `%{aor => binding}` (консоль/тесты)."
  @spec list(integer()) :: %{optional(String.t()) => binding()}
  def list(now_ms \\ now()) do
    @table
    |> :ets.tab2list()
    |> Enum.filter(fn {_aor, b} -> live?(b, now_ms) end)
    |> Map.new()
  end

  @impl true
  def init(_opts) do
    @table = :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    schedule_sweep()
    {:ok, %{}}
  end

  @impl true
  def handle_call({:register, aor, b}, _from, state) do
    :ets.insert(@table, {aor, b})
    {:reply, :ok, state}
  end

  def handle_call({:drop_aors, aors}, _from, state) do
    Enum.each(aors, &:ets.delete(@table, &1))
    {:reply, :ok, state}
  end

  def handle_call({:drop_number, number}, _from, state) do
    prefix = "sip:#{number}@"

    aors =
      for {aor, _b} <- :ets.tab2list(@table), String.starts_with?(aor, prefix), do: aor

    Enum.each(aors, &:ets.delete(@table, &1))
    {:reply, length(aors), state}
  end

  @impl true
  def handle_info(:sweep, state) do
    now = now()

    @table
    |> :ets.tab2list()
    |> Enum.each(fn {aor, b} ->
      unless live?(b, now), do: :ets.delete(@table, aor)
    end)

    schedule_sweep()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  defp live?(b, now_ms), do: b.expires_at > now_ms

  defp now, do: System.system_time(:millisecond)

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_ms)
end
