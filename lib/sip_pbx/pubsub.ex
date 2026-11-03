defmodule SipPbx.PubSub do
  @moduledoc """
  Простейший pub/sub поверх `Registry SipPbx.PubSub.Registry` (в надзирателе с
  Task 1): подписка на атомарный топик, доставка `send/2` без ожидания.
  Топики: `:sip_log`, `:call_event`, `:alert`.
  """

  @registry SipPbx.PubSub.Registry
  @topics [:sip_log, :call_event, :alert]

  @doc """
  Подписаться на все топики (`:sip_log`, `:call_event`, `:alert`) текущего
  процесса. Повторная подписка того же процесса не повторяет доставку —
  Registry хранит одну запись на пару (процесс, топик).
  """
  @spec subscribe() :: :ok
  def subscribe do
    Enum.each(@topics, &Registry.register(@registry, &1, nil))
  end

  @doc """
  Доставить сообщение всем подписчикам топика (`send/2`, без ожидания).
  """
  @spec broadcast(atom(), term()) :: :ok
  def broadcast(topic, message) do
    Registry.dispatch(@registry, topic, fn entries ->
      for {pid, _} <- entries, do: send(pid, message)
    end)

    :ok
  end
end
