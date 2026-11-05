defmodule SipPbx.SIP.TxClientTest do
  use ExUnit.Case, async: false

  alias SipPbx.{Alerts, Metrics}
  alias SipPbx.SIP.{Message, Transport, TxClient}
  alias SipPbxTest.UAC

  defmodule Sink do
    use GenServer
    def start_link(o), do: GenServer.start_link(__MODULE__, o)
    def init(o), do: {:ok, o}

    def handle_info(m, o),
      do:
        (
          send(o, {:seen, m})
          {:noreply, o}
        )
  end

  setup do
    {:ok, sink} = start_supervised({Sink, self()})
    {:ok, _} = Transport.start_link(port: 0, name: :tx_cli_t, router: sink)
    port = Transport.local_port(:tx_cli_t)

    # ретрансляты/таймауты этих тестов могут столкнуть правила Alerts на тике —
    # подтверждаем свои, чтобы active()-ассерты Task 14 не поплыли (carry из T6)
    on_exit(fn ->
      Alerts.ack(:retrans_spike)
      Alerts.ack(:tx_timeout_rate)
    end)

    # t1_ms=20 из config/test.exs: B/F = 1280 мс, шаг 20·2^n с потолком 160
    %{port: port}
  end

  defp req(method, branch) do
    %Message{
      type: :request,
      method: method,
      uri: "sip:x@y",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:5160;branch=#{branch}"},
        {"from", "<sip:a@y>;tag=t"},
        {"to", "<sip:b@y>"},
        {"call-id", "tc"},
        {"cseq", "7 " <> method},
        {"content-length", "0"}
      ]
    }
  end

  test "NICT на мёртвый порт: ретрансляты и таймаут F ≈ 64·T1", %{port: _} do
    # мёртвый порт: закрываем временный сокет сразу
    {:ok, dead} = :gen_udp.open(0)
    dead_port = elem(:inet.port(dead), 1)
    :gen_udp.close(dead)

    before = Metrics.get(:retrans)
    t0 = System.monotonic_time(:millisecond)

    {:ok, tx} =
      TxClient.start_link(
        transport: :tx_cli_t,
        owner: self(),
        ref: :r1,
        kind: :other,
        target: {{127, 0, 0, 1}, dead_port},
        msg: req("OPTIONS", "z9hG4bKD1")
      )

    ref = Process.monitor(tx)
    assert_receive {:tx_timeout, :r1}, 3000
    assert System.monotonic_time(:millisecond) - t0 >= 1_200
    assert Metrics.get(:retrans) - before >= 4

    # DOWN приходит только после реального выхода: без него проверка живости
    # гонится с terminate (там ещё и синхронный unreg_tx)
    assert_receive {:DOWN, ^ref, :process, ^tx, :normal}, 1000
    refute Process.alive?(tx)
  end

  test "ICT: 180 → {:tx_resp}, 2xx минует нас (роутеру), ACK от владельца гасит", %{
    port: _port
  } do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)

    {:ok, tx} =
      TxClient.start_link(
        transport: :tx_cli_t,
        owner: self(),
        ref: :r2,
        kind: :invite,
        target: {{127, 0, 0, 1}, uac_port},
        msg: req("INVITE", "z9hG4bKI1")
      )

    {:ok, inv} = UAC.recv(uac, 1000)
    assert inv.method == "INVITE"
    assert Message.branch(inv) == "z9hG4bKI1"

    UAC.send_resp(uac, inv, 180, "Ringing")
    assert_receive {:tx_resp, :r2, %Message{status_code: 180}}, 1000

    UAC.send_resp(uac, inv, 200, "OK")
    assert_receive {:seen, {:sip_2xx, %Message{status_code: 200}, _}}, 1000

    TxClient.stop(tx)
    # после гашения ретранслятов в UAC нет
    assert UAC.recv(uac, 400) == {:error, :timeout}
  end

  test "ICT: финальный 486 → {:tx_resp}; дубликат-ретранслят INVITE жив до stop", %{
    port: _port
  } do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)

    {:ok, tx} =
      TxClient.start_link(
        transport: :tx_cli_t,
        owner: self(),
        ref: :r3,
        kind: :invite,
        target: {{127, 0, 0, 1}, uac_port},
        msg: req("INVITE", "z9hG4bKI2")
      )

    {:ok, inv} = UAC.recv(uac, 1000)
    UAC.send_resp(uac, inv, 486, "Busy Here")
    assert_receive {:tx_resp, :r3, %Message{status_code: 486}}, 1000

    # Completed: запрос продолжает ретранслироваться (второй пакет в UAC)
    assert {:ok, %Message{method: "INVITE"}} = UAC.recv(uac, 600)
    TxClient.stop(tx)
  end
end
