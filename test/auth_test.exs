defmodule SipPbx.AuthTest do
  use ExUnit.Case, async: false

  alias SipPbx.{Alerts, Auth, Metrics}
  alias SipPbx.SIP.{Digest, Message}

  @ip {203, 0, 113, 1}

  defp register_req(auth_header \\ nil) do
    base = %Message{
      type: :request,
      method: "REGISTER",
      uri: "sip:1001@pbx.local",
      headers: [{"via", "SIP/2.0/UDP 203.0.113.1"}, {"call-id", "a1"}]
    }

    if auth_header,
      do: Message.put_header(base, "authorization", auth_header),
      else: base
  end

  defp auth_value(nonce, password, opts \\ []) do
    qop = Keyword.get(opts, :qop, "auth")
    nc = Keyword.get(opts, :nc, "00000001")
    cnonce = Keyword.get(opts, :cnonce, "cnc1")
    realm = "pbx.local"
    method = Keyword.get(opts, :method, "REGISTER")
    uri = Keyword.get(opts, :uri, "sip:1001@pbx.local")
    resp = Digest.response("1001", realm, password, method, uri, nonce, nc, cnonce)

    fields = ~s(username="1001",realm="#{realm}",nonce="#{nonce}",uri="#{uri}")

    fields =
      if qop,
        do: fields <> ~s(,qop=auth,nc=#{nc},cnonce="#{cnonce}",response="#{resp}"),
        else: fields <> ~s(,response="#{resp}")

    "Digest " <> fields
  end

  test "без Authorization — challenge с nonce" do
    {nonce, header} = Auth.challenge(@ip)
    assert is_binary(nonce)
    assert header =~ ~s(realm="pbx.local")
    assert header =~ "qop=\"auth\""
    assert {:challenge, h} = Auth.verify(register_req(), @ip)
    assert h =~ "nonce="
  end

  # nonce привязан к IP и мс выдачи: тесты одного прогона получают одинаковый
  # nonce в пределах миллисекунды, и nc-состояние/окно фейсов перетекают между
  # тестами — каждому свой IP
  test "верный digest — :ok; неверный пароль — :forbidden" do
    ip = {203, 0, 113, 2}
    {nonce, _} = Auth.challenge(ip)
    now = System.system_time(:millisecond)
    good = register_req(auth_value(nonce, "pass1001"))
    assert :ok == Auth.verify(good, ip, now_ms: now)

    bad = register_req(auth_value(nonce, "wrongpass", nc: "00000002"))
    assert :forbidden == Auth.verify(bad, ip, now_ms: now)
  end

  test "nc обязан расти: повтор nc — :forbidden (replay)" do
    ip = {203, 0, 113, 3}
    {nonce, _} = Auth.challenge(ip)
    now = System.system_time(:millisecond)
    msg = register_req(auth_value(nonce, "pass1001", nc: "00000005"))
    assert :ok == Auth.verify(msg, ip, now_ms: now)
    assert :forbidden == Auth.verify(msg, ip, now_ms: now)
  end

  test "просроченный nonce — {:stale, header со stale=true}" do
    ip = {203, 0, 113, 4}
    {nonce, _} = Auth.challenge(ip)
    stale_now = System.system_time(:millisecond) + 301_000
    msg = register_req(auth_value(nonce, "pass1001", nc: "00000001"))
    assert {:stale, h} = Auth.verify(msg, ip, now_ms: stale_now)
    assert h =~ "stale=true"
  end

  test "антибрутфорс: >10 неудач с IP за 30 с → бан + алерт auth_burst" do
    ip = {203, 0, 113, 99}
    {nonce, _} = Auth.challenge(ip)
    now = System.system_time(:millisecond)
    before = Metrics.get(:auth_fail)

    for i <- 1..11 do
      msg =
        register_req(
          auth_value(nonce, "wrong#{i}", nc: "0000#{String.pad_leading("#{i}", 4, "0")}")
        )

      assert :forbidden == Auth.verify(msg, ip, now_ms: now + i)
    end

    assert Alerts.blocked?(ip)
    assert Metrics.get(:auth_fail) - before >= 11
    assert Enum.any?(Alerts.active(), &(&1.rule == :auth_burst))
    Alerts.unblock(ip)
    Alerts.ack(:auth_burst)

    # block_ip поднимает ещё и :blocked_ip (Task 6) — без ack он остался бы
    # активным и сломал инвариант Alerts.active() == [] в alerts_test
    # (файлы гоняются в случайном порядке)
    Alerts.ack(:blocked_ip)
  end

  test "устаревшее окно фейлов обнуляется: >10 считаются в пределах 30 с" do
    ip = {203, 0, 113, 8}
    {nonce, _} = Auth.challenge(ip)
    now = System.system_time(:millisecond)

    # now_ms у now_ms-окна фейлов общий с проверкой nonce, а TTL nonce (5 мин)
    # больше окна (30 с) — сдвигаем часы на >окна, digest остаётся сверяемым
    fail = fn shift ->
      msg =
        register_req(
          auth_value(nonce, "wrong#{shift}",
            nc: String.pad_leading(Integer.to_string(shift, 16), 8, "0")
          )
        )

      assert :forbidden == Auth.verify(msg, ip, now_ms: now + shift)
    end

    for i <- 1..10, do: fail.(i)
    refute Alerts.blocked?(ip)

    # окно протухло — счётчик стартует заново, единственный фейл не банит
    fail.(31_001)
    refute Alerts.blocked?(ip)

    # и только >10 фейлов внутри одного живого окна
    for i <- 31_002..31_011, do: fail.(i)
    assert Alerts.blocked?(ip)
    assert Enum.any?(Alerts.active(), &(&1.rule == :auth_burst))

    Alerts.unblock(ip)
    Alerts.ack(:auth_burst)
    Alerts.ack(:blocked_ip)
  end

  test "INVITE читает Proxy-Authorization, REGISTER — Authorization" do
    ip = {203, 0, 113, 5}
    {nonce, _} = Auth.challenge(ip)
    now = System.system_time(:millisecond)
    uri = "sip:1002@pbx.local"

    invite = %Message{
      type: :request,
      method: "INVITE",
      uri: uri,
      headers: [{"via", "SIP/2.0/UDP 203.0.113.1"}, {"call-id", "i1"}]
    }

    value = auth_value(nonce, "pass1001", nc: "00000007", method: "INVITE", uri: uri)

    # INVITE с одним только Authorization не считается аутентифицированным —
    # для него ждём proxy-authorization (407-ветка, §22.2 спеки)
    assert {:challenge, _} =
             Auth.verify(Message.put_header(invite, "authorization", value), ip, now_ms: now)

    invite_auth = Message.put_header(invite, "proxy-authorization", value)
    assert :ok == Auth.verify(invite_auth, ip, now_ms: now)
  end
end
