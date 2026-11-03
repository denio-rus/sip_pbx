defmodule SipPbx.SIP.Message do
  @moduledoc """
  Парсер и билдер SIP-сообщений АТС (RFC 3261). Компактные имена раскрываются
  (§7.3.3): на входящих не придираемся к регистру и форме.
  """

  defstruct type: nil,
            # request
            method: nil,
            uri: nil,
            # response
            status_code: nil,
            reason: nil,
            version: "SIP/2.0",
            headers: [],
            body: ""

  @type t :: %__MODULE__{}

  # ---------------------------------------------------------------- Parsing

  @doc """
  Разобрать сырое SIP-сообщение. Имена заголовков нормализуются в нижний
  регистр, компактные имена раскрываются в полные (RFC 3261 §7.3.3) —
  ECSS-10 шлёт входящий INVITE компактно, и без этого `Call-ID`/`To`
  читались бы как nil (work_log sip_phone §9).

  ## Examples

      iex> case Message.parse("INVITE sip:bob@host SIP/2.0\\r\\ni: cid1\\r\\nf: <sip:alice@host>;tag=t1\\r\\n\\r\\n") do
      ...>   {:ok, m} -> Message.header(m, "call-id") <> " / " <> Message.header(m, "from")
      ...> end
      "cid1 / <sip:alice@host>;tag=t1"

  """
  @spec parse(binary()) :: {:ok, t()} | {:error, term()}
  def parse(data) when is_binary(data) do
    case String.split(data, "\r\n\r\n", parts: 2) do
      [head, body] -> parse_head(head, body)
      [head] -> parse_head(head, "")
      _ -> {:error, :malformed}
    end
  end

  defp parse_head(head, body) do
    case String.split(head, "\r\n") do
      [start_line | header_lines] ->
        with {:ok, %__MODULE__{} = base} <- parse_start_line(start_line),
             {:ok, headers} <- parse_headers(header_lines) do
          {:ok, %__MODULE__{base | headers: headers, body: body}}
        end

      _ ->
        {:error, :malformed}
    end
  end

  defp parse_start_line("SIP/2.0 " <> rest) do
    case Integer.parse(rest) do
      {code, rest2} ->
        reason = String.trim_leading(rest2, " ")
        {:ok, %__MODULE__{type: :response, status_code: code, reason: reason}}

      :error ->
        {:error, :bad_status_line}
    end
  end

  defp parse_start_line(line) do
    case String.split(line, " ", parts: 3) do
      [method, uri, "SIP/2.0"] ->
        {:ok, %__MODULE__{type: :request, method: method, uri: uri}}

      _ ->
        {:error, :bad_request_line}
    end
  end

  # Компактные имена заголовков (RFC 3261 §7.3.3 и приложения) -> полные имена.
  # ECSS-10, например, шлёт входящий INVITE компактно: v:, f:, t:, i:, m:, c:, l:
  @compact %{
    "v" => "via",
    "f" => "from",
    "t" => "to",
    "i" => "call-id",
    "m" => "contact",
    "e" => "content-encoding",
    "l" => "content-length",
    "c" => "content-type",
    "s" => "subject",
    "r" => "require",
    "k" => "supported",
    "j" => "call-info",
    "o" => "info",
    "b" => "referred-by",
    "u" => "allow",
    "g" => "accept-encoding",
    "x" => "session-expires"
  }

  defp parse_headers(lines) do
    headers =
      Enum.flat_map(lines, fn
        "" -> []
        line -> [String.split(line, ":", parts: 2)]
      end)
      |> Enum.filter(fn
        [_n, _v] -> true
        _ -> false
      end)
      |> Enum.map(fn [n, v] ->
        n = String.downcase(n)
        {@compact[n] || n, String.trim(v)}
      end)

    {:ok, headers}
  end

  # ------------------------------------------------------------- Accessors

  @doc """
  Первое значение заголовка (имя регистронезависимо), `nil` если нет.

  ## Examples

      iex> {:ok, m} = Message.parse("OPTIONS sip:x SIP/2.0\\r\\nAllow: INVITE\\r\\n\\r\\n")
      ...> Message.header(m, "ALLOW")
      "INVITE"

  """
  @spec header(t(), String.t()) :: String.t() | nil
  def header(%__MODULE__{headers: hs}, name) do
    name = String.downcase(name)

    case Enum.find(hs, fn {n, _} -> n == name end) do
      {_, v} -> v
      nil -> nil
    end
  end

  @doc """
  Все значения заголовка (для повторяемых вроде Via).

  ## Examples

      iex> {:ok, m} = Message.parse("OPTIONS sip:x SIP/2.0\\r\\nv: SIP/2.0/UDP a;branch=z1\\r\\nv: SIP/2.0/UDP b;branch=z2\\r\\n\\r\\n")
      ...> Message.headers(m, "via")
      ["SIP/2.0/UDP a;branch=z1", "SIP/2.0/UDP b;branch=z2"]

  """
  @spec headers(t(), String.t()) :: [String.t()]
  def headers(%__MODULE__{headers: hs}, name) do
    name = String.downcase(name)
    for {n, v} <- hs, n == name, do: v
  end

  @doc """
  Параметр из заголовка с параметрами (регистронезависимо).

  ## Examples

      iex> {:ok, m} = Message.parse("BYE sip:x SIP/2.0\\r\\nf: <sip:a@h>;tag=zz9\\r\\n\\r\\n")
      ...> Message.header_param(m, "from", "tag")
      "zz9"

  """
  @spec header_param(t(), String.t(), String.t()) :: String.t() | nil
  def header_param(msg, header_name, param) do
    case header(msg, header_name) do
      nil ->
        nil

      value ->
        param = String.downcase(param)

        Regex.run(~r/;\s*#{param}\s*=\s*"?([^;">\s]+)"?/i, value)
        |> case do
          [_, v] -> v
          _ -> nil
        end
    end
  end

  @doc """
  CSeq как `{число, МЕТОД}`.

  ## Examples

      iex> {:ok, m} = Message.parse("BYE sip:x SIP/2.0\\r\\ncseq: 3 bye\\r\\n\\r\\n")
      ...> Message.cseq(m)
      {3, "BYE"}

  """
  @spec cseq(t()) :: {non_neg_integer(), String.t()} | nil
  def cseq(%__MODULE__{} = msg) do
    case header(msg, "cseq") do
      nil ->
        nil

      v ->
        # Integer.parse, а не to_integer: входящий `CSeq: abc INVITE` — ошибка
        # формата (nil), а не крэш у каждого, кто читает CSeq (review Task 2).
        case String.split(v, " ", parts: 2) do
          [n, m] ->
            case Integer.parse(n) do
              {num, _rest} -> {num, String.upcase(m)}
              :error -> nil
            end

          _ ->
            nil
        end
    end
  end

  @doc false
  @spec branch(t()) :: String.t() | nil
  def branch(msg), do: header_param(msg, "via", "branch")

  @doc """
  URI из адресного заголовка From/To/Contact (`<sip:100@host>;tag=...`).

  ## Examples

      iex> {:ok, m} = Message.parse("BYE sip:x SIP/2.0\\r\\nto: <sip:101@host>;tag=zz\\r\\n\\r\\n")
      ...> Message.addr_uri(m, "to")
      "sip:101@host"

  """
  @spec addr_uri(t(), String.t()) :: String.t() | nil
  def addr_uri(msg, name) do
    case header(msg, name) do
      nil ->
        nil

      v ->
        case Regex.run(~r/<([^>]+)>/, v) do
          [_, uri] -> uri
          _ -> v |> String.split(";") |> hd() |> String.trim()
        end
    end
  end

  @doc """
  User-часть из sip-URI.

  ## Examples

      iex> Message.user_of("sip:101@10.107.1.124:5060")
      "101"

  """
  @spec user_of(String.t()) :: String.t()
  def user_of(uri) do
    uri
    |> String.replace(~r/^sip:/i, "")
    |> String.split("@")
    |> hd()
    |> String.split(":")
    |> hd()
  end

  # --------------------------------------------------------------- Builder

  @doc """
  Установить заголовок: **заменяет** существующий (имя регистронезависимо),
  а не добавляет дубликат — иначе 200 OK уезжал с двумя `Content-Length`
  (work_log sip_phone §5).

  ## Examples

      iex> %Message{type: :request, method: "OPTIONS", uri: "sip:x"}
      ...> |> Message.put_header("content-length", "5")
      ...> |> Message.put_header("Content-Length", "0")
      ...> |> Map.get(:headers)
      [{"content-length", "0"}]

  """
  @spec put_header(t(), String.t(), String.t()) :: t()
  def put_header(%__MODULE__{headers: hs} = msg, name, value) do
    name = String.downcase(name)

    if Enum.any?(hs, fn {n, _} -> n == name end) do
      %{msg | headers: Enum.map(hs, fn {n, v} -> if(n == name, do: {n, value}, else: {n, v}) end)}
    else
      %{msg | headers: hs ++ [{name, value}]}
    end
  end

  @doc """
  Добавить заголовок, не отменяя уже существующие — для повторяемых
  (Route, Record-Route: RFC 3261 §7.3, порядок заголовков значим).

  ## Examples

      iex> %Message{type: :request, method: "BYE", uri: "sip:x"}
      ...> |> Message.append_header("route", "<sip:p1;lr>")
      ...> |> Message.append_header("Route", "<sip:p2;lr>")
      ...> |> Map.get(:headers)
      [{"route", "<sip:p1;lr>"}, {"route", "<sip:p2;lr>"}]

  """
  @spec append_header(t(), String.t(), String.t()) :: t()
  def append_header(%__MODULE__{headers: hs} = msg, name, value) do
    %{msg | headers: hs ++ [{String.downcase(name), value}]}
  end

  @doc """
  Собрать сообщение в iodata: стартовая строка, заголовки в каноническом
  регистре (`call-id` → `Call-ID`), тело как есть. `Content-Length` —
  ответственность вызывающего (см. `put_header/3`).
  """
  @spec to_iodata(t()) :: iodata()
  def to_iodata(%__MODULE__{} = msg) do
    start =
      case msg.type do
        :request -> "#{msg.method} #{msg.uri} #{msg.version}"
        :response -> "#{msg.version} #{msg.status_code} #{msg.reason}"
      end

    headers =
      Enum.map(msg.headers, fn {n, v} ->
        "#{canonical_header_name(n)}: #{v}\r\n"
      end)

    body = msg.body || ""
    [start, "\r\n", headers, "\r\n", body]
  end

  @canonical %{
    "via" => "Via",
    "from" => "From",
    "to" => "To",
    "call-id" => "Call-ID",
    "cseq" => "CSeq",
    "contact" => "Contact",
    "content-type" => "Content-Type",
    "content-length" => "Content-Length",
    "content-disposition" => "Content-Disposition",
    "max-forwards" => "Max-Forwards",
    "authorization" => "Authorization",
    "www-authenticate" => "WWW-Authenticate",
    "proxy-authenticate" => "Proxy-Authenticate",
    "record-route" => "Record-Route",
    "min-expires" => "Min-Expires",
    "session-expires" => "Session-Expires",
    "call-info" => "Call-Info",
    "referred-by" => "Referred-By",
    "accept-encoding" => "Accept-Encoding",
    "info" => "Info",
    "subject" => "Subject",
    "error" => "Error",
    "warning" => "Warning",
    "allow" => "Allow",
    "supported" => "Supported",
    "require" => "Require",
    "expires" => "Expires",
    "retry-after" => "Retry-After",
    "reason" => "Reason",
    "route" => "Route",
    "user-agent" => "User-Agent"
  }

  defp canonical_header_name(name) do
    case Map.get(@canonical, name) do
      nil ->
        name
        |> String.split("-")
        |> Enum.map_join("-", &String.capitalize/1)

      c ->
        c
    end
  end

  @doc false
  @spec to_binary(t()) :: binary()
  def to_binary(msg), do: IO.iodata_to_binary(to_iodata(msg))

  @doc """
  Краткое человекочитаемое описание сообщения для лога.

  ## Examples

      iex> Message.summary(%Message{type: :response, status_code: 180, reason: "Ringing"})
      "180 Ringing"

  """
  @spec summary(t()) :: String.t()
  def summary(%__MODULE__{type: :request} = m) do
    "#{m.method} #{m.uri}"
  end

  def summary(%__MODULE__{type: :response} = m) do
    "#{m.status_code} #{m.reason}"
  end
end
