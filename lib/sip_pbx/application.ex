defmodule SipPbx.Application do
  @moduledoc """
  Надзиратель АТС: консистентные процессы (Location, Auth, Transport, Proxy,
  Metrics, Alerts) под `:one_for_one`; консоль — рядом, её падение не должно
  ронять телефонию.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :duplicate, name: SipPbx.PubSub.Registry}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: SipPbx.Supervisor)
  end
end
