defmodule SipPbx.SIP.DigestTest do
  use ExUnit.Case, async: true
  alias SipPbx.SIP.Digest

  doctest SipPbx.SIP.Digest

  # эталон RFC 2617 §3.5 (он же §C RFC 2069): Mufasa/testrealm@host.com/
  # "Circle Of Life", GET /dir/index.html, nonce dcd98b71...
  @ref %{
    username: "Mufasa",
    realm: "testrealm@host.com",
    password: "Circle Of Life",
    method: "GET",
    uri: "/dir/index.html",
    nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093"
  }

  # Векторы пересчитаны по формулам RFC 2617 §3.2.2 (в плане они были
  # перепутаны местами: 6629fae... — это значение КАК РАЗ с qop=auth из
  # примера §3.5, а классическая форма для тех же параметров — 670fd8c2...).
  test "response без qop — классическая форма H(A1):nonce:H(A2)" do
    assert Digest.response(
             "Mufasa",
             "testrealm@host.com",
             "Circle Of Life",
             "GET",
             "/dir/index.html",
             @ref.nonce,
             nil,
             nil
           ) == "670fd8c2df070c60b045671b8b24ff02"
  end

  test "response с qop=auth — эталон RFC 2617 §3.5 (nc=00000001, cnonce=0a4f113b)" do
    assert Digest.response(
             "Mufasa",
             "testrealm@host.com",
             "Circle Of Life",
             "GET",
             "/dir/index.html",
             @ref.nonce,
             "00000001",
             "0a4f113b"
           ) == "6629fae49393a05397450978507c4ef1"
  end

  test "nonce: подпись и свежесть" do
    ip = {192, 0, 2, 1}
    n = Digest.nonce("secret", ip, 1_000)
    assert :ok == Digest.check_nonce("secret", ip, n, 2_000, 300_000)
    assert {:error, :stale} == Digest.check_nonce("secret", ip, n, 400_000, 300_000)
    assert {:error, :bad} == Digest.check_nonce("secret", {192, 0, 2, 2}, n, 2_000, 300_000)
    assert {:error, :bad} == Digest.check_nonce("secret", ip, "мусор", 2_000, 300_000)
  end

  # Ключи карты — строки: имена полей приходят из недоверенного заголовка
  # (атомы из них не делаем — атомы не собираются GC), и все потребители
  # (Auth, UAC) читают auth["nonce"] / auth["response"].
  test "parse_auth разбирает qop-формат" do
    {:ok, m} =
      Digest.parse_auth(
        ~s(Digest username="1001", realm="pbx.local", nonce="n1", uri="sip:pbx", ) <>
          ~s(response="abcd", qop=auth, nc=00000001, cnonce="xyz")
      )

    assert m["username"] == "1001" and m["nc"] == "00000001"
    assert m["qop"] == "auth" and m["cnonce"] == "xyz"
  end

  test "parse_auth без username/response или не-Digest — :error" do
    assert :error == Digest.parse_auth(~s(Digest realm="pbx.local", nonce="n1"))
    assert :error == Digest.parse_auth("Basic dXNlcjpwYXNz")
  end

  test "verify считает digest и зовёт проверку nonce" do
    auth = %{
      "username" => "Mufasa",
      "realm" => "testrealm@host.com",
      "nonce" => @ref.nonce,
      "uri" => "/dir/index.html",
      "response" => "670fd8c2df070c60b045671b8b24ff02"
    }

    assert :ok == Digest.verify(auth, "Circle Of Life", "GET", fn _ -> :ok end)
    assert {:error, :bad_digest} == Digest.verify(auth, "wrong", "GET", fn _ -> :ok end)

    assert {:error, :stale} ==
             Digest.verify(auth, "Circle Of Life", "GET", fn _ -> {:error, :stale} end)
  end
end
