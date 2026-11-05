defmodule SipPbx.Application do
  @moduledoc """
  Надзиратель АТС: консистентные процессы (Location, Auth, Registrar, Transport,
  Proxy, LogBuffer, Metrics, Alerts) под `:one_for_one`, транзакции — ephemeral-детьми
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
      # после Alerts: антибрутфорс зовёт block_ip/fire
      SipPbx.Auth,
      # контейнер ephemeral-транзакций (§17): дети :temporary
      SipPbx.SIP.TxSupervisor,
      # роутер транспорта до Proxy (Task 13); ДО Transport — тот шлёт ему
      # почтой по имени, по незарегистрированному имени send/2 падает
      SipPbx.Registrar,
      {SipPbx.SIP.Transport, router: SipPbx.Registrar}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: SipPbx.Supervisor)
  end
end
