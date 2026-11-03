defmodule SipPbx.SIP.Digest do
  @moduledoc """
  HTTP digest (RFC 2617) для SIP-аутентификации: stateless nonce на HMAC-SHA256,
  пересчёт digest, разбор/сборка заголовков. Чистые функции — время и секрет
  приходят аргументами, чтобы тесты не зависели от процессов (свежесть/nc/бан
  поверх них навешивает `SipPbx.Auth`, Task 10).
  """

  @doc """
  Stateless nonce: `base64url("ms|ip|hmac")`. Подпись привязана к IP — чужой
  украденный nonce не переиспользуется.

  ## Examples

      iex> n = SipPbx.SIP.Digest.nonce("s", {127, 0, 0, 1}, 123)
      iex> SipPbx.SIP.Digest.check_nonce("s", {127, 0, 0, 1}, n, 456, 1_000)
      :ok

  """
  @spec nonce(binary(), :inet.ip_address(), integer()) :: String.t()
  def nonce(secret, ip, ms) do
    payload = "#{ms}|#{:inet.ntoa(ip)}"
    mac = mac_of(secret, payload)
    Base.url_encode64(payload <> "|" <> mac, padding: false)
  end

  @doc "Проверка подписи, принадлежности IP и свежести; просроченный — `:stale`."
  @spec check_nonce(binary(), :inet.ip_address(), String.t(), integer(), integer()) ::
          :ok | {:error, :stale | :bad}
  def check_nonce(secret, ip, encoded, now_ms, lifetime_ms) do
    with {:ok, decoded} <- Base.url_decode64(encoded, padding: false),
         [ms_s, ip_s, mac] <- String.split(decoded, "|", parts: 3),
         true <- eq?(mac, mac_of(secret, "#{ms_s}|#{ip_s}")),
         true <- ip_s == to_string(:inet.ntoa(ip)),
         {ms, ""} <- Integer.parse(ms_s) do
      if now_ms - ms > lifetime_ms, do: {:error, :stale}, else: :ok
    else
      _ -> {:error, :bad}
    end
  end

  @doc """
  MD5 digest. `nc/cnonce` — при `qop=auth`, иначе `nil` (классическая форма).

  ## Examples

      iex> SipPbx.SIP.Digest.response("Mufasa", "testrealm@host.com", "Circle Of Life",
      ...>   "GET", "/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
      ...>   "00000001", "0a4f113b")
      "6629fae49393a05397450978507c4ef1"

  """
  @spec response(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t() | nil,
          String.t() | nil
        ) :: String.t()
  def response(username, realm, password, method, uri, nonce, nc, cnonce) do
    a1 = md5("#{username}:#{realm}:#{password}")
    a2 = md5("#{method}:#{uri}")

    raw =
      if is_nil(nc) or is_nil(cnonce) do
        "#{a1}:#{nonce}:#{a2}"
      else
        "#{a1}:#{nonce}:#{nc}:#{cnonce}:auth:#{a2}"
      end

    md5(raw)
  end

  @doc """
  Значение `WWW-Authenticate`/`Proxy-Authenticate`; `opts: [stale: true]` —
  после протухания nonce (клиент повторяет запрос с новым nonce, не меняя
  учётные данные, RFC 2617 §2.2).
  """
  @spec challenge_header(String.t(), String.t(), String.t(), keyword()) :: String.t()
  def challenge_header(realm, nonce, opaque, opts \\ []) do
    stale = if opts[:stale], do: ", stale=true", else: ""

    ~s(Digest realm="#{realm}", nonce="#{nonce}", opaque="#{opaque}", ) <>
      ~s(qop="auth", algorithm=MD5#{stale})
  end

  @doc """
  Разбор значения `Authorization`/`Proxy-Authorization` в карту со строковыми
  ключами (`auth["nonce"]`): имена полей приходят из недоверенного заголовка,
  атомы из них не делаем. Имена приводятся к нижнему регистру, кавычки снимаются.

  ## Examples

      iex> {:ok, m} = SipPbx.SIP.Digest.parse_auth(~s(Digest username="1001", response="abcd"))
      iex> m["username"]
      "1001"

  """
  @spec parse_auth(String.t()) :: {:ok, map()} | :error
  def parse_auth("Digest " <> rest) do
    pairs =
      for [_, k, v] <- Regex.scan(~r/([A-Za-z-]+)=("[^"]*"|[^,\s]+)/, rest) do
        {String.downcase(k), String.trim(v, ~s("))}
      end

    m = Map.new(pairs)

    if Map.has_key?(m, "username") and Map.has_key?(m, "response") do
      {:ok, m}
    else
      :error
    end
  end

  def parse_auth(_), do: :error

  @doc """
  Сверка `Authorization` (карта из `parse_auth/1`): сначала callback проверки
  nonce (`Auth` передаёт свою проверку свежести/подписи/nc), затем пересчёт
  digest — ответы не подсказывают, что именно не так.

  ## Examples

      iex> auth = %{"username" => "Mufasa", "realm" => "testrealm@host.com",
      ...>   "nonce" => "dcd98b7102dd2f0e8b11d0f600bfb0c093",
      ...>   "uri" => "/dir/index.html",
      ...>   "response" => "670fd8c2df070c60b045671b8b24ff02"}
      iex> SipPbx.SIP.Digest.verify(auth, "Circle Of Life", "GET", fn _ -> :ok end)
      :ok

  """
  @spec verify(map(), String.t(), String.t(), (map() -> :ok | {:error, term()})) ::
          :ok | {:error, :stale | :bad_nonce | :bad_digest}
  def verify(auth, password, method, nonce_check) do
    case extract_fields(auth) do
      {:ok, username, realm, nonce, uri, expected} ->
        with :ok <- nonce_check.(auth) do
          got =
            response(username, realm, password, method, uri, nonce, auth["nc"], auth["cnonce"])

          if eq?(got, expected), do: :ok, else: {:error, :bad_digest}
        end

      :error ->
        {:error, :bad_nonce}
    end
  end

  # Обязательные поля RFC 2617 §2.2; отсутствие любого — битый challenge-ответ,
  # для `Auth` это тот же путь, что и неверный digest (`:bad_nonce` → 401/407).
  defp extract_fields(auth) do
    with username when is_binary(username) <- auth["username"],
         realm when is_binary(realm) <- auth["realm"],
         nonce when is_binary(nonce) <- auth["nonce"],
         uri when is_binary(uri) <- auth["uri"],
         response when is_binary(response) <- auth["response"] do
      {:ok, username, realm, nonce, uri, response}
    else
      _ -> :error
    end
  end

  defp mac_of(secret, payload),
    do: :crypto.mac(:hmac, :sha256, secret, payload) |> Base.encode16(case: :lower)

  defp md5(s), do: :crypto.hash(:md5, s) |> Base.encode16(case: :lower)

  # MAC сверяем через хэш, а не посимвольным `==` — время сравнения не
  # выдаёт положение первого отличающегося байта.
  defp eq?(a, b) do
    byte_size(a) == byte_size(b) and :crypto.hash(:sha256, a) == :crypto.hash(:sha256, b)
  end
end
