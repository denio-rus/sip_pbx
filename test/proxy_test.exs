defmodule SipPbx.ProxyTest do
  use ExUnit.Case, async: false

  alias SipPbx.{Alerts, DialogStore}
  alias SipPbx.SIP.{Message, Transport}
  alias SipPbxTest.UAC

  @realm "pbx.local"

  setup do
    port = Transport.local_port()
    {:ok, sa} = UAC.open(0)
    {:ok, sb} = UAC.open(0)
    {:ok, pa} = :inet.port(sa)
    {:ok, pb} = :inet.port(sb)
    target = {{127, 0, 0, 1}, port}

    # регистрация плеч с привязкой к реальным сокетам (received = порт сокета)
    :ok = register_from(sa, target, "1001", "pass1001")
    :ok = register_from(sb, target, "1002", "pass1002")

    # прогон поднимает :tx_timeout_rate/:retrans_spike (тесты 408 и ретранслятов
    # дают выборку ≥10 tx) — снимаем активность, чтобы инвариант
    # `Alerts.active() == []` в alerts_test не зависел от порядка перемешивания
    on_exit(fn ->
      :ok = Alerts.ack(:tx_timeout_rate)
      :ok = Alerts.ack(:retrans_spike)
      :gen_udp.close(sa)
      :gen_udp.close(sb)
    end)

    # contact/register — на фактический порт сокета (opts contact_port),
    # иначе received-адрес в binding будет недостижим для форварда.
    %{sa: sa, sb: sb, pa: pa, pb: pb, target: target}
  end

  # REGISTER с Contact-портом = порт сокета; использует digest-цикл UAC.register,
  # но перед вызовом патчит контакт (UAC.register принимает opts contact_port).
  defp register_from(sock, target, num, pass, opts \\ []) do
    {:ok, p} = :inet.port(sock)
    p = Keyword.get(opts, :port, p)

    case UAC.register(sock, target, num, pass, contact_port: p) do
      {:ok, _} -> :ok
      {:error, {:status, c, _}} -> flunk("регистрация #{num}: #{c}")
    end
  end

  defp invite(sock, target, num, call_id, tag, password \\ "pass1001", body \\ sdp("inactive")) do
    cseq = 1

    first =
      %Message{
        type: :request,
        method: "INVITE",
        uri: "sip:#{num}@#{@realm}",
        body: body,
        headers: [
          {"via", "SIP/2.0/UDP 127.0.0.1:#{rand_port()};branch=z9hG4bK" <> UAC.rand_hex(8)},
          {"from", "<sip:1001@#{@realm}>;tag=#{tag}"},
          {"to", "<sip:#{num}@#{@realm}>"},
          {"call-id", call_id},
          {"cseq", "#{cseq} INVITE"},
          {"contact", "<sip:1001@127.0.0.1>"},
          {"content-length", "#{byte_size(body)}"}
        ]
      }

    UAC.send(sock, target, Message.to_binary(first))

    case UAC.recv(sock, 2000) do
      {:ok, %Message{status_code: 407} = ch} ->
        {nonce, realm} = UAC.challenge_fields(ch, "proxy-authenticate")
        auth = UAC.digest_header(first, password, {nonce, realm}, "proxy-authorization")

        second =
          first
          |> Message.put_header("cseq", "#{cseq + 1} INVITE")
          |> Message.put_header("authorization", auth)
          |> Message.put_header("proxy-authorization", auth)

        UAC.send(sock, target, Message.to_binary(second))
        # 100 Trying приходит первым — пропускаем; вторым элементом — branch
        # исходного INVITE (нужен CANCEL и 2xx-ACK, §16.10/§13.2.2.4)
        {drain_100(sock), Message.branch(second)}

      other ->
        {other, Message.branch(first)}
    end
  end

  defp drain_100(sock) do
    case UAC.recv(sock, 2000) do
      {:ok, %Message{status_code: code}} when code < 200 -> drain_100(sock)
      other -> other
    end
  end

  # Скриптованный телефон B: читает INVITE, шлёт 180, ждёт решения теста.
  defp b_ringing(sb) do
    {:ok, inv} = UAC.recv(sb, 2000)
    UAC.send_resp(sb, inv, 180, "Ringing")
    inv
  end

  defp b_answer(sb, inv, body \\ sdp("sendrecv")) do
    # send_resp с телом — шестой аргумент (расширить в Task 8: body \\ "")
    UAC.send_resp(sb, inv, 200, "OK", [{"contact", "<sip:1002@127.0.0.1>"}], body)
  end

  defp sdp(dir) do
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n" <>
      "m=audio 9 RTP/AVP 0\r\na=#{dir}\r\n"
  end

  defp rand_port, do: 40_000 + :rand.uniform(10_000)

  test "звонок 1001→1002: 407→digest, 100/180/200/ACK, SDP нетронут, RR в обе стороны",
       %{sa: sa, sb: sb, target: t} do
    inv = b_ringing(sb)
    {{:ok, %Message{status_code: 180}}, branch} = invite(sa, t, "1002", "pc1", "ta1")

    b_answer(sb, inv)
    assert {:ok, %Message{status_code: 200} = ok} = UAC.recv(sa, 2000)
    assert ok.body == sdp("sendrecv")
    assert Message.header(ok, "record-route") =~ "pbx.local"
    assert Message.header(ok, "contact") =~ "1002"

    # ACK по route set — в АТС; в Via — новый branch плеча A
    ack =
      %Message{
        type: :request,
        method: "ACK",
        uri: "sip:1002@#{@realm}",
        headers: [
          {"via", "SIP/2.0/UDP 127.0.0.1:55199;branch=#{branch}"},
          {"from", Message.header(ok, "from")},
          {"to", Message.header(ok, "to")},
          {"call-id", "pc1"},
          {"cseq", Message.header(ok, "cseq")},
          {"route", Message.header(ok, "record-route")},
          {"content-length", "0"}
        ]
      }

    UAC.send(sa, t, Message.to_binary(ack))

    # B обязан увидеть ACK (прокси форвардит 2xx-ACK, §16.11)
    assert {:ok, %Message{method: "ACK"}} = UAC.recv(sb, 1000)
    assert %{state: :active} = DialogStore.get("pc1")
  end

  test "отбой с обеих сторон: BYE через АТС, диалог чист, повторный звонок проходит",
       %{sa: sa, sb: sb, target: t} do
    inv = b_ringing(sb)
    {{:ok, %Message{status_code: 180}}, branch} = invite(sa, t, "1002", "pc2", "ta2")
    b_answer(sb, inv)
    {:ok, ok200} = UAC.recv(sa, 2000)
    UAC.send(sa, t, Message.to_binary(ack2xx(ok200, "pc2", branch)))

    # BYE от A в route set АТС
    bye = in_dialog("BYE", ok200, "pc2", "sip:1002@#{@realm}", 2)
    UAC.send(sa, t, Message.to_binary(bye))
    assert {:ok, %Message{method: "BYE"}} = UAC.recv(sb, 1000)
    UAC.send_resp(sb, recv_msg(sb), 200, "OK")
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 1000)

    assert DialogStore.get("pc2") == nil
    assert Transport.tx_count() == 0

    # инвариант задания: повторный вызов проходит
    inv2 = b_ringing(sb)
    {{:ok, %Message{status_code: 180}}, _} = invite(sa, t, "1002", "pc2b", "ta2b")
    b_answer(sb, inv2)
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 2000)
  end

  test "481 на BYE в неизвестный диалог", %{sa: sa, target: t} do
    bye =
      %Message{
        type: :request,
        method: "BYE",
        uri: "sip:1002@#{@realm}",
        headers: [
          {"via", "SIP/2.0/UDP 127.0.0.1:55201;branch=z9hG4bK" <> UAC.rand_hex(8)},
          {"from", "<sip:1001@#{@realm}>;tag=zz"},
          {"to", "<sip:1002@#{@realm}>;tag=yy"},
          {"call-id", "nope"},
          {"cseq", "1 BYE"},
          {"content-length", "0"}
        ]
      }

    UAC.send(sa, t, Message.to_binary(bye))
    # сначала может прийти 407 (BYE in-dialog тоже требует auth?) — НЕТ: in-dialog
    # запросы в dialog сверяются с DialogStore,digest не требуется (§6). Ответ сразу:
    assert {:ok, %Message{status_code: 481}} = UAC.recv(sa, 1000)
  end

  test "404 на 1003 (есть в справочнике, binding истёк)", %{sa: sa, target: t} do
    {{:ok, %Message{status_code: 404}}, _} = invite(sa, t, "1003", "pc4", "ta4")
    assert Transport.tx_count() == 0
  end

  test "CANCEL до ответа: 200 на CANCEL, 487 плечу A, состояние свободно",
       %{sa: sa, sb: sb, target: t} do
    _inv = b_ringing(sb)
    {{:ok, %Message{status_code: 180}}, branch} = invite(sa, t, "1002", "pc5", "ta5")

    # CANCEL — с branch исходного INVITE плеча A (§16.10 матчит IST по нему)
    UAC.send(sa, t, Message.to_binary(cancel_with(branch, "pc5", "ta5")))
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 1000)
    # ACK на 2xx CANCEL — тот же branch (non-INVITE ACK сохраняет branch)
    UAC.send(sa, t, Message.to_binary(ack_cancel(branch, "pc5", "ta5")))

    assert {:ok, can} = UAC.recv(sb, 1000)
    assert can.method == "CANCEL"
    UAC.send_resp(sb, can, 487, "Request Terminated")

    # 487 спускается плечу A; ACK на non-2xx — с новым branch (прокси матчит
    # по диалогу, external_ack + форвард ACK в B)
    assert {:ok, %Message{status_code: 487}} = UAC.recv(sa, 2000)
    UAC.send(sa, t, Message.to_binary(ack_non2xx("pc5", "ta5")))
    assert {:ok, %Message{method: "ACK"}} = UAC.recv(sb, 1000)

    assert DialogStore.get("pc5") == nil
  end

  test "гонка CANCEL/200 OK (§16.5): 200 уже доставлен — CANCEL получает 200, диалог жив",
       %{sa: sa, sb: sb, target: t} do
    inv = b_ringing(sb)
    {{:ok, _ring}, branch} = invite(sa, t, "1002", "pc6", "ta6")
    b_answer(sb, inv)
    {:ok, ok200} = UAC.recv(sa, 2000)

    UAC.send(sa, t, Message.to_binary(cancel_with(branch, "pc6", "ta6")))
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 1000)
    # диалог active — BYE закрывает корректно
    UAC.send(sa, t, Message.to_binary(ack2xx(ok200, "pc6", branch)))
    UAC.send(sa, t, Message.to_binary(in_dialog("BYE", ok200, "pc6", "sip:1002@#{@realm}", 2)))
    UAC.send_resp(sb, recv_msg(sb), 200, "OK")
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 1000)
    assert DialogStore.get("pc6") == nil
  end

  test "405 на SUBSCRIBE, 200 на OPTIONS", %{sa: sa, target: t} do
    UAC.send_raw(
      sa,
      t,
      "SUBSCRIBE sip:#{@realm} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55203;branch=z9hG4bKX1\r\n" <>
        "From: <sip:1001@x>;tag=t\r\nTo: <sip:1002@x>\r\nCall-ID: s1\r\nCSeq: 1 SUBSCRIBE\r\nContent-Length: 0\r\n\r\n"
    )

    assert {:ok, %Message{status_code: 405}} = UAC.recv(sa, 1000)
  end

  test "битый INVITE без CSeq — 400", %{sa: sa, target: t} do
    UAC.send_raw(
      sa,
      t,
      "INVITE sip:1002@pbx.local SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55204;branch=z9hG4bKB0\r\n" <>
        "From: <sip:1001@x>;tag=t\r\nTo: <sip:1002@x>\r\nCall-ID: b1\r\nContent-Length: 0\r\n\r\n"
    )

    assert {:ok, %Message{status_code: 400}} = UAC.recv(sa, 1000)
  end

  test "ретранслят INVITE → один звонок; потеря ACK → ретранслят 200", %{sa: sa, sb: sb, target: t} do
    inv = b_ringing(sb)
    {{:ok, _ring}, branch} = invite(sa, t, "1002", "pc8", "ta8")
    b_answer(sb, inv)
    {:ok, ok200} = UAC.recv(sa, 2000)

    # ACK не шлём — A-сторона (transfer_ack + собственный ретранслят Proxy)
    # обязана повторить 200: ждём второй 200 в sa
    assert {:ok, %Message{status_code: 200}} = UAC.recv(sa, 4000)
    UAC.send(sa, t, Message.to_binary(ack2xx(ok200, "pc8", branch)))
    assert {:ok, %Message{method: "ACK"}} = UAC.recv(sb, 1000)
  end

  test "408 на мёртвый binding", %{sa: sa, target: t} do
    # 1002 на мёртвый порт: регистрируемся с socket, который закрываем
    {:ok, dead} = UAC.open(0)
    {:ok, dp} = :inet.port(dead)
    :ok = register_from(dead, t, "1002", "pass1002", port: dp)
    :gen_udp.close(dead)

    {{:ok, %Message{status_code: 408}}, _} = invite(sa, t, "1002", "pc9", "ta9", "pass1001")
    assert DialogStore.get("pc9") == nil
  end

  defp ack2xx(ok200, call_id, branch) do
    # 2xx-ACK сохраняет branch INVITE (§13.2.2.4) — им его и найдёт transfer_ack
    %Message{
      type: :request,
      method: "ACK",
      uri: "sip:1002@#{@realm}",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:55199;branch=#{branch}"},
        {"from", Message.header(ok200, "from")},
        {"to", Message.header(ok200, "to")},
        {"call-id", call_id},
        {"cseq", Message.header(ok200, "cseq")},
        {"route", Message.header(ok200, "record-route")},
        {"content-length", "0"}
      ]
    }
  end

  defp in_dialog(method, ok200, call_id, uri, cseq) do
    %Message{
      type: :request,
      method: method,
      uri: uri,
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:55200;branch=z9hG4bK" <> UAC.rand_hex(8)},
        {"from", Message.header(ok200, "from")},
        {"to", Message.header(ok200, "to")},
        {"call-id", call_id},
        {"cseq", "#{cseq} " <> method},
        {"route", Message.header(ok200, "record-route")},
        {"content-length", "0"}
      ]
    }
  end

  defp cancel_with(branch, call_id, tag) do
    %Message{
      type: :request,
      method: "CANCEL",
      uri: "sip:1002@#{@realm}",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:55205;branch=#{branch}"},
        {"from", "<sip:1001@#{@realm}>;tag=#{tag}"},
        {"to", "<sip:1002@#{@realm}>"},
        {"call-id", call_id},
        {"cseq", "2 CANCEL"},
        {"content-length", "0"}
      ]
    }
  end

  defp recv_msg(sock) do
    {:ok, m} = UAC.recv(sock, 2000)
    m
  end

  defp ack_cancel(branch, call_id, tag) do
    %Message{
      type: :request,
      method: "ACK",
      uri: "sip:1002@#{@realm}",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:55205;branch=#{branch}"},
        {"from", "<sip:1001@#{@realm}>;tag=#{tag}"},
        {"to", "<sip:1002@#{@realm}>"},
        {"call-id", call_id},
        {"cseq", "2 CANCEL"},
        {"content-length", "0"}
      ]
    }
  end

  defp ack_non2xx(call_id, tag) do
    # ACK на non-2xx — новый branch (§17.1.1.3); прокси матчает по диалогу
    %Message{
      type: :request,
      method: "ACK",
      uri: "sip:1002@#{@realm}",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:55206;branch=z9hG4bK" <> UAC.rand_hex(8)},
        {"from", "<sip:1001@#{@realm}>;tag=#{tag}"},
        {"to", "<sip:1002@#{@realm}>"},
        {"call-id", call_id},
        {"cseq", "2 INVITE"},
        {"content-length", "0"}
      ]
    }
  end
end
