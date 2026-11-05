defmodule SipPbx.DialogStore.Dialog do
  @moduledoc """
  Структура диалога для `SipPbx.DialogStore`: плечи A/B, состояние стейк-машины
  прокси и моменты переходов.
  """

  @typedoc "Плечо диалога: номер, AOR-URI, сырой Contact, адрес доставки, route_set, свой tag и адрес ответа из Via (`received`/`rport`)."
  @type leg :: map()

  @typedoc "Фаза диалога: setting-up → `:proceeding`, подтверждён (200 OK) → `:active`, живая запись удалена при штатном BYE; `:terminated` — умер без BYE (аномалия трассировки)."
  @type state :: :proceeding | :active | :terminated

  @type t :: %__MODULE__{
          call_id: String.t(),
          state: state(),
          a: leg() | nil,
          b: leg() | nil,
          started_at: integer() | nil,
          active_at: integer() | nil
        }

  @enforce_keys [:call_id]
  defstruct [:call_id, :started_at, state: :proceeding, a: nil, b: nil, active_at: nil]
end

defmodule SipPbx.DialogStore do
  @moduledoc """
  Хранилище диалогов прокси (Task 13): диалог на Call-ID, читает и пишет кто
  угодно напрямую — горячий путь обработки in-dialog запросов не должен ждать
  GenServer'а.

  Хранение — одна ETS `:public` `:sip_pbx_dialogs` (ключ `call_id`), как
  `:sip_pbx_banned` в `SipPbx.Alerts`: `get/1` и `find_in_dialog/3` читают без
  обращения к процессу. Владелец таблицы — `GenServer` ниже, он существует
  только ради времени жизни именованной таблицы; записи идут `:ets`-вызовами
  прямо из процесса-писателя. Окно перезапуска владельца — таблица живёт до
  пересоздания, а после смерти владельца её нет и прямые обращения дают
  `:badarg` (carry из ревью Task 5, см. `SipPbx.SIP.Transport.blocked?/1`):
  для писателя в горячем пути это приемлемый трейд-офф против синхронного
  `call` на каждый переход диалога.
  """

  use GenServer

  alias SipPbx.DialogStore.Dialog

  @table :sip_pbx_dialogs

  @type leg :: Dialog.leg()
  @type dialog :: Dialog.t()

  @doc """
  Запустить хранилище: создать ETS-таблицу `:sip_pbx_dialogs` (`:public`,
  ключ — `call_id`). Процесс-владелец ничего не обрабатывает — только время
  жизни таблицы.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Положить/перезаписать диалог по `call_id`."
  @spec put(dialog()) :: :ok
  def put(%Dialog{call_id: call_id} = dialog) do
    :ets.insert(@table, {call_id, dialog})
    :ok
  end

  @doc "Диалог по `call_id` либо `nil`."
  @spec get(String.t()) :: dialog() | nil
  def get(call_id) do
    case :ets.lookup(@table, call_id) do
      [{^call_id, dialog}] -> dialog
      [] -> nil
    end
  end

  @doc """
  Обновить диалог функцией `dialog -> dialog`: `:ets`-обновление из процесса
  писателя, параллельные обновители одного `call_id` могут потерять запись друг
  друга — диалоги одного вызова обслуживает одна ветка Proxy. Возвращает
  обновлённый диалог либо `nil`, если записи уже нет (BYE успел удалить).
  """
  @spec update(String.t(), (dialog() -> dialog())) :: dialog() | nil
  def update(call_id, fun) do
    case get(call_id) do
      %Dialog{} = dialog ->
        updated = fun.(dialog)
        :ets.insert(@table, {call_id, updated})
        updated

      nil ->
        nil
    end
  end

  @doc "Удалить диалог (штатный финал: BYE → 200 OK)."
  @spec delete(String.t()) :: :ok
  def delete(call_id) do
    :ets.delete(@table, call_id)
    :ok
  end

  @doc """
  Найти плечо диалога по тегу стороны: `from_tag`/`to_tag` in-dialog запроса,
  порядок не важен — возвращаем то плечо, чей `tag` встретился (`{:a, leg}` /
  `{:b, leg}`), при неизвестном `call_id` или чужом теге — `nil`.
  """
  @spec find_in_dialog(String.t(), String.t() | nil, String.t() | nil) ::
          {:a, leg()} | {:b, leg()} | nil
  def find_in_dialog(call_id, from_tag, to_tag) do
    tags = [from_tag, to_tag]

    case get(call_id) do
      %Dialog{} = d ->
        [{:a, d.a}, {:b, d.b}]
        |> Enum.find(fn {_name, leg} ->
          is_map(leg) and Map.get(leg, :tag) != nil and Map.get(leg, :tag) in tags
        end)

      nil ->
        nil
    end
  end

  @doc "Живые диалоги (для консоли): всё, что ещё не `:terminated`."
  @spec all() :: [dialog()]
  def all do
    @table
    |> :ets.tab2list()
    |> Enum.map(fn {_call_id, dialog} -> dialog end)
    |> Enum.reject(&(&1.state == :terminated))
  end

  @impl true
  def init(_opts) do
    @table = :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}
end
