defmodule SipPbx.Application do
  @moduledoc """
  Надзиратель АТС: консистентные процессы (Location, Auth, Transport, Proxy,
  LogBuffer, Metrics, Alerts) под `:one_for_one`, транзакции — ephemeral-детьми
  через `SipPbx.SIP.TxSupervisor`; консоль — рядом, её падение не должно ронять
  телефонию.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :duplicate, name: SipPbx.PubSub.Registry},
      {SipPbx.LogBuffer, capacity: 2000},
      SipPbx.Metrics,
      SipPbx.Location,
      SipPbx.Alerts,
      # роутер-заглушка до Registrar (Task 11) / Proxy (Task 13)
      SipPbx.SIP.RouterSink,
      # контейнер ephemeral-транзакций (§17): дети :temporary
      SipPbx.SIP.TxSupervisor,
      {SipPbx.SIP.Transport, router: SipPbx.SIP.RouterSink}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: SipPbx.Supervisor)
  end
end
