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
    resp = UAC.send_resp(uac, inv, 486, "Busy Here")
    assert_receive {:tx_resp, :r3, %Message{status_code: 486}}, 1000

    # §17.1.2.2: retransmitted final в Completed доставляется владельцу повторно
    # (Proxy по нему повторяет ACK) — дубль ответа шлём напрямую в транзакцию,
    # маршрутизацию по branch Transport покрыл своими тестами
    send(tx, {:tx_resp, resp, {{127, 0, 0, 1}, 5060}})
    assert_receive {:tx_resp, :r3, %Message{status_code: 486}}, 1000

    # Completed: запрос продолжает ретранслироваться (второй пакет в UAC)
    assert {:ok, %Message{method: "INVITE"}} = UAC.recv(uac, 600)
    TxClient.stop(tx)
  end
end

defmodule SipPbx.SIP.TxServerTest do
  use ExUnit.Case, async: false

  alias SipPbx.{Alerts, Metrics}
  alias SipPbx.SIP.{Message, Transport, TxServer}
  alias SipPbxTest.{EchoRouter, UAC}

  setup do
    # эхо-роутер жив ДО транспорта: Transport шлёт роутеру send/2 по имени,
    # неподписанное имя уронило бы транспорт на первом же пакете
    {:ok, _echo} = EchoRouter.start_link(name: :tx_srv_echo, transport: :tx_cli_t)
    {:ok, _} = Transport.start_link(port: 0, name: :tx_cli_t, router: :tx_srv_echo)
    port = Transport.local_port(:tx_cli_t)

    # Timer G/H этих тестов копят :retrans/:tx_timeout — подтверждаем свои
    # алерты, чтобы active()-ассерты Task 14 не поплыли (carry из T6)
    on_exit(fn ->
      Alerts.ack(:retrans_spike)
      Alerts.ack(:tx_timeout_rate)
    end)

    %{port: port}
  end

  defp build_resp(req, code, reason) do
    %Message{
      type: :response,
      status_code: code,
      reason: reason,
      headers: [
        {"via", Message.header(req, "via")},
        {"from", Message.header(req, "from")},
        {"to", Message.header(req, "to")},
        {"call-id", Message.header(req, "call-id")},
        {"cseq", Message.header(req, "cseq")},
        {"content-length", "0"}
      ]
    }
  end

  defp invite_raw(branch) do
    "INVITE sip:b@y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:#{uac_fixed()};branch=#{branch}\r\n" <>
      "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sc\r\nCSeq: 3 INVITE\r\n" <>
      "Content-Length: 0\r\n\r\n"
  end

  defp uac_fixed, do: 55161

  test "IST: дубликат INVITE получает повтор 100 и 180; ACK гасит", %{port: port} do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)
    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, invite_raw("z9hG4bKS1"))

    {:ok, inv} = UAC.recv(uac, 1000)

    {:ok, tx} =
      TxServer.start_link(
        transport: :tx_cli_t,
        owner: self(),
        kind: :invite,
        msg: inv,
        from: {{127, 0, 0, 1}, uac_port}
      )

    tx_ref = Process.monitor(tx)

    TxServer.trying(tx)
    assert {:ok, %Message{status_code: 100}} = UAC.recv(uac, 1000)
    TxServer.respond(tx, build_resp(inv, 180, "Ringing"), false)
    assert {:ok, %Message{status_code: 180}} = UAC.recv(uac, 1000)

    # ретранслят INVITE (тот же branch) — повтор 180, логика не тревожится
    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, invite_raw("z9hG4bKS1"))
    assert {:ok, %Message{status_code: 180}} = UAC.recv(uac, 1000)

    TxServer.respond(tx, build_resp(inv, 486, "Busy Here"), true)
    assert {:ok, %Message{status_code: 486}} = UAC.recv(uac, 1000)
    # IST completed: сама ретранслирует 486 (Timer G)
    assert {:ok, %Message{status_code: 486}} = UAC.recv(uac, 600)

    # ACK с тем же branch — гасит транзакцию
    UAC.send_raw(
      uac,
      {{127, 0, 0, 1}, port},
      "ACK sip:y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:#{uac_port};branch=z9hG4bKS1\r\n" <>
        "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sc\r\nCSeq: 3 INVITE\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )

    assert_receive {:tx_acked, {"z9hG4bKS1", "INVITE", 3}}, 1000

    # после гибели terminate снял ОБА ключа (запроса и ACK) — DOWN приходит
    # только после завершения terminate, гонки с tx_count нет
    assert_receive {:DOWN, ^tx_ref, :process, ^tx, _}, 1000
    assert Transport.tx_count(:tx_cli_t) == 0
  end

  test "NIST на BYE: final 200, дубликат → повтор 200, ACK гасит", %{port: port} do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)

    bye =
      "BYE sip:b@y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55162;branch=z9hG4bKB1\r\n" <>
        "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sb\r\nCSeq: 5 BYE\r\n" <>
        "Content-Length: 0\r\n\r\n"

    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, bye)
    {:ok, req} = UAC.recv(uac, 1000)

    from = {{127, 0, 0, 1}, uac_port}

    {:ok, tx} =
      TxServer.start_link(transport: :tx_cli_t, owner: self(), kind: :other, msg: req, from: from)

    # реестрированы ОБА ключа — запроса и ACK ("ACK:" <> метод из CSeq);
    # lookup_tx нужен и Proxy'у для матчинга CANCEL (§16.10)
    assert Transport.lookup_tx(:tx_cli_t, {:srv, "z9hG4bKB1", "BYE", 5, from}) == tx
    assert Transport.lookup_tx(:tx_cli_t, {:srv, "z9hG4bKB1", "ACK:BYE", 5, from}) == tx

    TxServer.respond(tx, build_resp(req, 200, "OK"), true)
    assert {:ok, %Message{status_code: 200}} = UAC.recv(uac, 1000)

    # дубликат BYE — сам NIST ретранслирует 200 (получил дубликат → таймер, §17.2.2)
    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, bye)
    assert {:ok, %Message{status_code: 200}} = UAC.recv(uac, 1000)

    UAC.send_raw(
      uac,
      {{127, 0, 0, 1}, port},
      "ACK sip:b@y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55162;branch=z9hG4bKB1\r\n" <>
        "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sb\r\nCSeq: 5 BYE\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )

    assert_receive {:tx_acked, {"z9hG4bKB1", "BYE", 5}}, 1000
  end

  test "IST без ACK: Timer H (64·T1) гасит транзакцию и будит владельца", %{port: port} do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)
    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, invite_raw("z9hG4bKS9"))
    {:ok, inv} = UAC.recv(uac, 1000)

    {:ok, tx} =
      TxServer.start_link(
        transport: :tx_cli_t,
        owner: self(),
        kind: :invite,
        msg: inv,
        from: {{127, 0, 0, 1}, uac_port}
      )

    TxServer.respond(tx, build_resp(inv, 603, "Decline"), true)
    t0 = System.monotonic_time(:millisecond)
    # H = 64·20 = 1280 мс в тесте
    assert_receive {:tx_timeout_owner, {"z9hG4bKS9", "INVITE", 3}}, 2500
    assert System.monotonic_time(:millisecond) - t0 >= 1_100
    refute Process.alive?(tx)
  end

  test "ACK раньше финального ответа (§17.2.1 гонка) — доставлен, но не гасит", %{port: port} do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)
    from = {{127, 0, 0, 1}, uac_port}
    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, invite_raw("z9hG4bKS7"))
    {:ok, inv} = UAC.recv(uac, 1000)

    {:ok, tx} =
      TxServer.start_link(
        transport: :tx_cli_t,
        owner: self(),
        kind: :invite,
        msg: inv,
        from: from
      )

    # ACK обогнал final: §17.2.1 требует доставки тушке и вне Completed,
    # но транзакция живёт и отвечает штатно (Proxy T13 ждёт {:tx_acked, ref}
    # для ре-форварда ACK)
    UAC.send_raw(
      uac,
      {{127, 0, 0, 1}, port},
      "ACK sip:y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:#{uac_port};branch=z9hG4bKS7\r\n" <>
        "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sc\r\nCSeq: 3 INVITE\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )

    assert_receive {:tx_acked, {"z9hG4bKS7", "INVITE", 3}}, 1000
    assert Process.alive?(tx)

    TxServer.respond(tx, build_resp(inv, 486, "Busy Here"), true)
    assert {:ok, %Message{status_code: 486}} = UAC.recv(uac, 1000)

    # ранний выход после дела (тот же путь, что документирует respond/3)
    TxServer.stop(tx)
  end

  test "NIST: истечение D (64·T1) — тихая гибель, ни письма, ни :tx_timeout", %{port: port} do
    {:ok, uac} = UAC.open(0)
    {:ok, uac_port} = :inet.port(uac)
    from = {{127, 0, 0, 1}, uac_port}

    bye =
      "BYE sip:b@y SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55164;branch=z9hG4bKB9\r\n" <>
        "From: <sip:a@y>;tag=t\r\nTo: <sip:b@y>\r\nCall-ID: sd\r\nCSeq: 5 BYE\r\n" <>
        "Content-Length: 0\r\n\r\n"

    UAC.send_raw(uac, {{127, 0, 0, 1}, port}, bye)
    {:ok, req} = UAC.recv(uac, 1000)

    {:ok, tx} =
      TxServer.start_link(transport: :tx_cli_t, owner: self(), kind: :other, msg: req, from: from)

    ref = Process.monitor(tx)
    TxServer.respond(tx, build_resp(req, 200, "OK"), true)
    assert {:ok, %Message{status_code: 200}} = UAC.recv(uac, 1000)

    # D = 64·20 = 1280 мс; DOWN guarantee: всё, что транзакция могла послать,
    # уже в mailbox — значит письмо про D не приходит вовсе (фикс Important 1)
    assert_receive {:DOWN, ^ref, :process, ^tx, :normal}, 2000
    refute_receive {:tx_timeout_owner, _}, 50
  end
end
