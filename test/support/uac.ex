defmodule SipPbxTest.UAC do
  @moduledoc """
  Низкоуровневый тестовый UAC: пассивный UDP-сокет и примитивы — открыть,
  отправить сырые байты (`send_raw/3`), принять и распарсить следующий
  SIP-пакет (`recv/2`), ответить на принятый запрос корректным ответом
  (`send_resp/4–6`). Ответ уходит UDP-отправителю последнего `recv/2` этого
  сокета, поэтому читать запрос и отвечать надо в одном процессе.
  Сценарные хелперы: `register/5` — полный REGISTER-цикл с digest (Task 11);
  сценарии вызова добавит Proxy (Task 13).
  """

  alias SipPbx.SIP.Message

  @type sock :: :gen_udp.socket()

  @doc """
  Открыть пассивный UDP-сокет (порт 0 — эфемерный), чтобы читать ответы
  через `recv/2`, а не почтой процесса.
  """
  @spec open(:inet.port_number()) :: {:ok, sock()} | {:error, term()}
  def open(port) do
    :gen_udp.open(port, [:binary])
  end

  @doc """
  Отправить сырые байты в `target` — `{ip, port}`.
  """
  @spec send(sock(), {tuple(), :inet.port_number()}, iodata()) :: :ok | {:error, term()}
  def send(sock, {ip, port}, data) do
    :gen_udp.send(sock, ip, port, data)
  end

  @doc "То же, что `send/3` — имя читается лучше в транзакционных тестах."
  @spec send_raw(sock(), {tuple(), :inet.port_number()}, iodata()) :: :ok | {:error, term()}
  def send_raw(sock, target, data), do: send(sock, target, data)

  @doc """
  Ждать следующий пакет до `timeout` мс и разобрать его; таймаут —
  `{:error, :timeout}`. Синхронный `:gen_udp.recv/3` на этом OTP возвращает
  `{:error, :einval}` (проверено пробником), поэтому приём — временный
  `active: :once` и `receive` в процессе-читателе: чужая почта в mailbox
  остаётся на месте. Запоминает UDP-адрес отправителя (в processes-dictionary
  вызывающего) — в него же поедет ответ `send_resp/4–6`.
  """
  @spec recv(sock(), timeout()) :: {:ok, Message.t()} | {:error, term()}
  def recv(sock, timeout) do
    :ok = :inet.setopts(sock, active: :once)

    receive do
      {:udp, ^sock, ip, port, data} ->
        passive(sock)
        Process.put(last_from_key(sock), {ip, port})
        Message.parse(data)
    after
      timeout ->
        passive(sock)
        {:error, :timeout}
    end
  end

  @doc """
  Собрать и отправить ответ на принятый запрос: все Via исходного сообщения
  (RFC 3261 §18.2.1), From/To/Call-ID/CSeq из запроса, дополнительные
  `headers`, тело `body` с честным Content-Length. Адресат — UDP-отправитель
  последнего `recv/2` этого сокета. Возвращает собранный `%Message{}`.
  """
  @spec send_resp(
          sock(),
          Message.t(),
          integer(),
          String.t(),
          [{String.t(), String.t()}],
          String.t()
        ) ::
          Message.t()
  def send_resp(sock, req, code, reason, headers \\ [], body \\ "") do
    {ip, port} = last_from(sock)

    msg =
      Message.build_response(req, code, reason)

    msg =
      Enum.reduce(headers, msg, fn {name, value}, acc ->
        Message.append_header(acc, name, value)
      end)
      |> Message.put_header("content-length", to_string(byte_size(body)))
      |> Map.put(:body, body)

    :ok = send(sock, {ip, port}, Message.to_iodata(msg))
    msg
  end

  @doc """
  Полный REGISTER-цикл: 401 → digest-повтор в том же диалоге → 200.
  Call-ID и From tag постоянны в обоих запросах, CSeq+1 (регрессия ECSS-10,
  work_log sip_phone §6). Финальный ответ != 2xx отдаётся как
  `{:error, {:status, code, msg}}`.

  Опция `:contact_port` (по умолчанию 55555) — порт в Contact: сценариям
  Proxy (Task 13) нужен реальный порт сокета, иначе адрес в Contact
  недостижим для форварда.
  """
  @spec register(sock(), {tuple(), :inet.port_number()}, String.t(), String.t(), keyword()) ::
          {:ok, Message.t()} | {:error, {:status, integer(), Message.t()} | term()}
  def register(sock, target, number, password, opts \\ []) do
    expires = Keyword.get(opts, :expires, 300)
    call_id = "reg-" <> rand_hex(6)
    tag = rand_hex(4)
    cseq = Keyword.get(opts, :cseq_start, 1)
    realm = Keyword.get(opts, :realm, "pbx.local")
    timeout = Keyword.get(opts, :timeout, 2000)
    # порт Contact = порт сокета (Task 13): binding.received и так берётся из
    # UDP-источника, но форвард/отладка должны видеть достижимый адрес в Contact
    contact_port = Keyword.get(opts, :contact_port, 55_555)

    first = register_raw(number, realm, call_id, tag, cseq, expires, contact_port)
    send(sock, target, Message.to_binary(first))

    case recv(sock, timeout) do
      {:ok, %Message{status_code: 401} = ch} ->
        {nonce, realm} = challenge_fields(ch, "www-authenticate")
        auth = digest_header(first, password, {nonce, realm}, "authorization")

        second =
          first
          |> Message.put_header("cseq", "#{cseq + 1} REGISTER")
          |> Message.put_header("authorization", auth)

        send(sock, target, Message.to_binary(second))
        recv(sock, timeout) |> normalize_status()

      other ->
        normalize_status(other)
    end
  end

  @doc """
  Достаёт {nonce, realm} из заголовка challenge. `Digest.parse_auth/1` для
  этого не годится — он разбор `Authorization`-ОТВЕТА (требует username и
  response), а challenge — серверная строка без них; поля берём регуляркой.
  """
  @spec challenge_fields(Message.t(), String.t()) :: {String.t() | nil, String.t() | nil}
  def challenge_fields(msg, header) do
    case Message.header(msg, header) do
      nil -> {nil, nil}
      v -> {challenge_param(v, "nonce"), challenge_param(v, "realm")}
    end
  end

  defp challenge_param(value, name) do
    case Regex.run(~r/\b#{name}\s*=\s*"?([^",\s]+)"?/i, value) do
      [_, v] -> v
      _ -> nil
    end
  end

  @doc "Считает Authorization/Proxy-Authorization для повтора запроса."
  @spec digest_header(
          Message.t(),
          String.t(),
          {String.t(), String.t()},
          String.t()
        ) :: String.t()
  def digest_header(req, password, {nonce, realm}, _scheme_header) do
    [username] =
      Regex.run(~r/<sip:(\d+)@/, Message.header(req, "from") || "", capture: :all_but_first)

    # nc отправляем ровно в том виде, в каком считали по нему digest, —
    # любой reformat между хэшем и заголовком ломает сверку
    nc = "00000001"
    cnonce = rand_hex(8)
    uri = req.uri

    resp =
      SipPbx.SIP.Digest.response(username, realm, password, req.method, uri, nonce, nc, cnonce)

    ~s(Digest username="#{username}",realm="#{realm}",nonce="#{nonce}",uri="#{uri}",) <>
      ~s(qop=auth,nc=#{nc},cnonce="#{cnonce}",response="#{resp}")
  end

  @doc false
  @spec rand_hex(pos_integer()) :: String.t()
  def rand_hex(n) do
    n
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  defp register_raw(number, realm, call_id, tag, cseq, expires, contact_port) do
    %Message{
      type: :request,
      method: "REGISTER",
      uri: "sip:#{number}@#{realm}",
      headers: [
        {"via", "SIP/2.0/UDP 127.0.0.1:#{rand_port()};branch=z9hG4bK" <> rand_hex(8)},
        {"from", "<sip:#{number}@#{realm}>;tag=#{tag}"},
        {"to", "<sip:#{number}@#{realm}>"},
        {"call-id", call_id},
        {"cseq", "#{cseq} REGISTER"},
        {"contact", "<sip:#{number}@127.0.0.1:#{contact_port};transport=udp>"},
        {"expires", "#{expires}"},
        {"content-length", "0"}
      ]
    }
  end

  # интерфейс register/5 — {:ok, msg} только для 2xx, прочий финал — {:error, {:status, …}}
  defp normalize_status({:ok, %Message{status_code: code} = msg}) when code not in 200..299,
    do: {:error, {:status, code, msg}}

  defp normalize_status(other), do: other

  defp rand_port, do: 50_000 + :rand.uniform(10_000)

  defp passive(sock), do: :inet.setopts(sock, active: false)

  defp last_from_key(sock), do: {__MODULE__, :last_from, sock}

  defp last_from(sock) do
    case Process.get(last_from_key(sock)) do
      nil -> raise "UAC.send_resp: на этом сокете ещё не было recv/2 — неизвестен адресат ответа"
      from -> from
    end
  end
end
