defmodule SipPbxTest.EchoRouter do
  @moduledoc """
  Тестовый роутер транспорта «эхо»: каждый новый запрос (`{:sip_new_request,
  msg, from}`) отправляет обратно отправителю через тот же транспорт. Нужен
  транзакционным тестам (Task 9), чтобы «поймать» свой же запрос через
  `UAC.recv/2` и завести по нему транзакцию — как это делает живой роутер,
  только без логики.
  """

  use GenServer

  alias SipPbx.SIP.{Message, Transport}

  @doc "Запустить эхо-роутер, отвечающий через транспорт `:transport`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @impl true
  def init(opts), do: {:ok, %{transport: Keyword.fetch!(opts, :transport)}}

  @impl true
  def handle_info({:sip_new_request, msg, from}, state) do
    Transport.send_msg(state.transport, from, Message.to_iodata(msg))
    {:noreply, state}
  end

  # 2xx на чужие INVITE и прочая почта — мимо
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}
end
