defmodule SipPbx.RegistrarTest do
  use ExUnit.Case, async: false

  alias SipPbx.Location
  alias SipPbx.SIP.Message
  alias SipPbxTest.UAC

  setup do
    # приложение поднято test_helper'ом (Task 1): Transport+Registrar работают
    port = SipPbx.SIP.Transport.local_port()
    {:ok, sock} = UAC.open(0)

    # binding живёт min_expires (60 с) и переживает тест: без уборки при
    # неудачном порядке LocationTest увидел бы чужие bindings в list/1
    on_exit(fn ->
      Location.unregister("sip:1001@pbx.local")
      Location.unregister("sip:1002@pbx.local")
    end)

    %{sock: sock, target: {{127, 0, 0, 1}, port}}
  end

  test "1001: 401 → digest → 200, binding с received виден в Location", %{sock: s, target: t} do
    assert {:ok, %Message{status_code: 200} = ok} = UAC.register(s, t, "1001", "pass1001")
    assert Message.header(ok, "contact") =~ "expires="
    assert %{received: {{127, 0, 0, 1}, _}} = Location.lookup("sip:1001@pbx.local")
  end

  test "1002 регистрируется параллельно 1001", %{sock: s, target: t} do
    assert {:ok, _} = UAC.register(s, t, "1002", "pass1002")
    assert map_size(Location.list()) >= 1
  end

  test "неверный пароль и неизвестный номер — 403, не подсказываем", %{sock: s, target: t} do
    assert {:error, {:status, 403, _}} = UAC.register(s, t, "1001", "badpass")
    assert {:error, {:status, 403, _}} = UAC.register(s, t, "9999", "x")
  end

  test "Expires: 0 снимает binding", %{sock: s, target: t} do
    {:ok, _} = UAC.register(s, t, "1001", "pass1001")
    assert {:ok, _} = UAC.register(s, t, "1001", "pass1001", expires: 0, cseq_start: 10)
    assert Location.lookup("sip:1001@pbx.local") == nil
  end

  test "Expires ниже min — 423 с Min-Expires", %{sock: s, target: t} do
    {:error, {:status, 423, resp}} = UAC.register(s, t, "1001", "pass1001", expires: 30)
    assert Message.header(resp, "min-expires") == "60"
  end

  test "OPTIONS → 200 с Allow, SUBSCRIBE → 405", %{sock: s, target: t} do
    UAC.send_raw(
      s,
      t,
      "OPTIONS sip:pbx.local SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55161;branch=z9hG4bKO1\r\n" <>
        "From: <sip:o@x>;tag=t\r\nTo: <sip:o@x>\r\nCall-ID: o1\r\nCSeq: 1 OPTIONS\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )

    assert {:ok, %Message{status_code: 200}} = UAC.recv(s, 1000)

    UAC.send_raw(
      s,
      t,
      "SUBSCRIBE sip:pbx.local SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:55161;branch=z9hG4bKO2\r\n" <>
        "From: <sip:o@x>;tag=t\r\nTo: <sip:o@x>\r\nCall-ID: o2\r\nCSeq: 1 SUBSCRIBE\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )

    assert {:ok, %Message{status_code: 405}} = UAC.recv(s, 1000)
  end
end
