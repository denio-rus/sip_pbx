defmodule SipPbx.SIP.TxSupervisor do
  @moduledoc """
  Контейнер ephemeral-транзакций: `DynamicSupervisor`
  `SipPbx.SIP.TransactionSupervisor`, в который Registrar/Proxy заводят
  `SipPbx.SIP.TxServer`/`SipPbx.SIP.TxClient` на каждую транзакцию.
  Политика детей — `:temporary` (§17: транзакция смертна, завершившаяся не
  должна быть воскрешена, а упавшая — повторена надзирателем за спиной
  владельца); сами модули тоже объявляют `restart: :temporary`, `tx_child_spec/2`
  фиксирует это явно.
  """

  use Supervisor

  @doc "Запустить надзиратель транзакций под именем `__MODULE__`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Child-spec транзакции для `DynamicSupervisor.start_child/2`:
  `{SipPbx.SIP.TxServer, opts}` с форсированным `:temporary`.
  """
  @spec tx_child_spec(module(), keyword()) :: Supervisor.child_spec()
  def tx_child_spec(tx_mod, opts) do
    Supervisor.child_spec({tx_mod, opts}, restart: :temporary)
  end

  @impl true
  def init(_opts) do
    children = [
      Supervisor.child_spec(
        {DynamicSupervisor, name: SipPbx.SIP.TransactionSupervisor, strategy: :one_for_one},
        id: SipPbx.SIP.TransactionSupervisor,
        # сам контейнер — permanent (его потеря останавливает приём транзакций
        # до рестарта приложения); ephemeral-политика — у детей-транзакций
        restart: :permanent
      )
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
