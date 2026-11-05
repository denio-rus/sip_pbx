defmodule SipPbx.SIP.TransportTest do
  use ExUnit.Case, async: false

  alias SipPbx.Metrics
  alias SipPbx.SIP.{Message, Transport}
  alias SipPbxTest.UAC

  defmodule RouterStub do
    use GenServer
    def start_link(owner), do: GenServer.start_link(__MODULE__, owner)
    def init(owner), do: {:ok, owner}

    def handle_info(msg, owner),
      do:
        (
          send(owner, {:seen, msg})
          {:noreply, owner}
        )
  end

  setup do
    {:ok, router} = start_supervised({RouterStub, self()})
    {:ok, _} = Transport.start_link(port: 0, name: :t_under_test, router: router)
    {:ok, sock} = UAC.open(0)
    %{sock: sock, port: Transport.local_port(:t_under_test)}
  end

  @via "Via: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK77\r\n"
  @base "From: <sip:x@y>\r\nTo: <sip:pbx>\r\nCall-ID: c\r\nContent-Length: 0\r\n\r\n"

  test "новый запрос — роутеру; дубликат — владельцу server-транзакции",
       %{sock: sock, port: port} do
    req = "OPTIONS sip:pbx SIP/2.0\r\n" <> @via <> "CSeq: 1 OPTIONS\r\n" <> @base
    UAC.send(sock, {{127, 0, 0, 1}, port}, req)
    assert_receive {:seen, {:sip_new_request, %Message{method: "OPTIONS"}, from}}, 1000

    :ok = Transport.reg_tx(:t_under_test, {:srv, "z9hG4bK77", "OPTIONS", 1, from}, self(), :srv)
    UAC.send(sock, {{127, 0, 0, 1}, port}, req)
    assert_receive {:tx_dup, %Message{method: "OPTIONS"}, ^from}, 1000
    assert Metrics.get(:pkt_dup) >= 1
  end

  test "ответ — владельцу клиентской транзакции по branch", %{sock: sock, port: port} do
    :ok = Transport.reg_tx(:t_under_test, {:cli, "z9hG4bK77"}, self(), :cli_other)
    assert Transport.tx_count(:t_under_test) == 1

    UAC.send(
      sock,
      {{127, 0, 0, 1}, port},
      "SIP/2.0 200 OK\r\n" <> @via <> "CSeq: 1 OPTIONS\r\n" <> @base
    )

    assert_receive {:tx_resp, %Message{status_code: 200}, {{127, 0, 0, 1}, _}}, 1000
    :ok = Transport.unreg_tx(:t_under_test, {:cli, "z9hG4bK77"})
    assert Transport.tx_count(:t_under_test) == 0
  end

  test "2xx на INVITE минует транзакцию — роутеру (§17.1.1.3)", %{sock: sock, port: port} do
    Transport.reg_tx(:t_under_test, {:cli, "z9hG4bKI"}, self(), :cli_invite)

    UAC.send(
      sock,
      {{127, 0, 0, 1}, port},
      "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bKI\r\n" <>
        "CSeq: 1 INVITE\r\n" <> @base
    )

    assert_receive {:seen, {:sip_2xx, %Message{status_code: 200}, _}}, 1000
    refute_receive {:tx_resp, _, _}, 50
  end

  test "битый пакет и осиротевший ответ — не краш, транспорт жив",
       %{sock: sock, port: port} do
    UAC.send(sock, {{127, 0, 0, 1}, port}, "это не sip\r\n\r\n")

    UAC.send(
      sock,
      {{127, 0, 0, 1}, port},
      "SIP/2.0 404 Not Found\r\n" <> @via <> "CSeq: 9 OPTIONS\r\n" <> @base
    )

    refute_receive {:seen, _}, 300

    req = "OPTIONS sip:pbx SIP/2.0\r\n" <> @via <> "CSeq: 2 OPTIONS\r\n" <> @base
    UAC.send(sock, {{127, 0, 0, 1}, port}, req)
    assert_receive {:seen, {:sip_new_request, %Message{method: "OPTIONS"}, _}}, 1000
    assert Metrics.get(:parse_fail) >= 1
  end
end
