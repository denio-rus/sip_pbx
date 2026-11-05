defmodule SipPbxTest.UAC do
  @moduledoc """
  Низкоуровневый тестовый UAC: пассивный UDP-сокет и примитивы — открыть,
  отправить сырые байты (`send_raw/3`), принять и распарсить следующий
  SIP-пакет (`recv/2`), ответить на принятый запрос корректным ответом
  (`send_resp/4–6`). Ответ уходит UDP-отправителю последнего `recv/2` этого
  сокета, поэтому читать запрос и отвечать надо в одном процессе.
  Сценарные хелперы (register/invite/…) добавит Task 11.
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
      %Message{type: :response, status_code: code, reason: reason}
      |> append_vias(req)
      |> copy_header(req, "from")
      |> copy_header(req, "to")
      |> copy_header(req, "call-id")
      |> copy_header(req, "cseq")

    msg =
      Enum.reduce(headers, msg, fn {name, value}, acc ->
        Message.append_header(acc, name, value)
      end)
      |> Message.put_header("content-length", to_string(byte_size(body)))
      |> Map.put(:body, body)

    :ok = send(sock, {ip, port}, Message.to_iodata(msg))
    msg
  end

  defp append_vias(msg, req),
    do: Enum.reduce(Message.headers(req, "via"), msg, &Message.append_header(&2, "via", &1))

  defp copy_header(msg, req, name) do
    case Message.header(req, name) do
      nil -> msg
      value -> Message.put_header(msg, name, value)
    end
  end

  defp passive(sock), do: :inet.setopts(sock, active: false)

  defp last_from_key(sock), do: {__MODULE__, :last_from, sock}

  defp last_from(sock) do
    case Process.get(last_from_key(sock)) do
      nil -> raise "UAC.send_resp: на этом сокете ещё не было recv/2 — неизвестен адресат ответа"
      from -> from
    end
  end
end
