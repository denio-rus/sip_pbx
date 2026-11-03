defmodule SipPbx.SIP.MessageTest do
  use ExUnit.Case, async: true
  alias SipPbx.SIP.Message

  doctest SipPbx.SIP.Message

  test "компактные имена раскрыты (входящий INVITE от ECSS-подобного UA)" do
    {:ok, m} =
      Message.parse(
        "INVITE sip:1002@pbx SIP/2.0\r\nv: SIP/2.0/UDP 1.1.1.1;branch=z9hG4bKx\r\n" <>
          "f: <sip:1001@pbx>;tag=t1\r\nt: <sip:1002@pbx>\r\ni: cid\r\n\r\n"
      )

    assert Message.header(m, "call-id") == "cid"
    assert Message.header_param(m, "from", "tag") == "t1"
    assert Message.branch(m) == "z9hG4bKx"
  end

  test "битые сообщения — ошибка, не краш" do
    assert {:error, _} = Message.parse("закат Солнца вручную")
    assert {:error, _} = Message.parse("SIP/2.0 неЧисло Ошибка\r\n\r\n")
  end

  test "нечисловой CSeq — nil, без крэша (parse пропускает, читатель не падает)" do
    {:ok, m} = Message.parse("INVITE sip:1002@pbx SIP/2.0\r\ncseq: abc INVITE\r\n\r\n")
    assert Message.cseq(m) == nil
  end

  test "канонический регистр при сборке + повторяемые заголовки по порядку" do
    bin =
      %Message{type: :request, method: "INVITE", uri: "sip:1002@pbx"}
      |> Message.put_header("call-id", "c1")
      |> Message.append_header("record-route", "<sip:pbx;lr>")
      |> Message.append_header("record-route", "<sip:p2;lr>")
      |> Message.to_binary()

    assert bin =~ "Call-ID: c1"
    assert bin =~ "Record-Route: <sip:pbx;lr>\r\nRecord-Route: <sip:p2;lr>"
  end
end
