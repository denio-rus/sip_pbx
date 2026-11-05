defmodule SipPbx.Registrar do
  @moduledoc """
  Регистратор (спека §5): первый живой роутер `Transport` — принимает
  `{:sip_new_request, msg, from}`, заводит серверную транзакцию (§17.2) и
  терминирует REGISTER: digest-challenge 401 → сверка → `200` с Contact и
  согласованным `expires`, `403` без подсказок, `423 Min-Expires`, снятие
  binding по `Expires: 0`. OPTIONS отвечает `200` с `Allow` (keepalive
  софтофонов — осознанно вне спеки, §6 «не придираемся»), прочие методы — 405.
  Ретранслят финала ведёт IST (NIST гаснет по D сама), поэтому письма
  `{:tx_acked | :tx_timeout_owner | :tx_dup, ...}` здесь игнорируются.
  """

  use GenServer

  alias SipPbx.{Auth, Location, Metrics}
  alias SipPbx.SIP.{Message, Transport, TxServer, TxSupervisor}

  # OPTIONS keepalive и 405 (§21.4.8 требует Allow в обоих)
  @allow "REGISTER, INVITE, ACK, CANCEL, BYE"

  @doc "Запустить регистратор под именем `__MODULE__` (роутер Transport)."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  AOR из Request-URI: `sip:<user>@<host>` (спека §5.1 — host берётся из URI,
  не из config-`realm`; параметры URI и порт отбрасываются, user — как в
  `Message.user_of/1`). Это же читает Proxy (Task 13) при маршрутизации.
  """
  @spec aor_of(Message.t()) :: String.t()
  def aor_of(%Message{uri: uri}) when is_binary(uri) do
    host =
      uri
      |> String.replace(~r/^sips?:/i, "")
      |> String.split("@")
      |> List.last()
      |> String.split([";", ":"])
      |> hd()

    "sip:#{Message.user_of(uri)}@#{host}"
  end

  @doc """
  Вся логика REGISTER (§5 спеки), публична для тестов; роутер вызывает её сам
  уже внутри серверной транзакции `tx`. Порядок: цикл-Via → `Auth.verify` →
  разбер `Expires` (заголовок, иначе параметр `expires` первого Contact, иначе
  `max_expires`) → 0/423/успех.
  """
  @spec handle_register(Message.t(), Transport.from(), GenServer.server()) :: :ok
  def handle_register(%Message{} = msg, from, tx) do
    ip = elem(from, 0)
    aor = aor_of(msg)
    now_ms = System.system_time(:millisecond)

    if loop_detected?(msg) do
      respond(tx, msg, 403, "Loop Detected")
    else
      case Auth.verify(msg, ip) do
        {:challenge, h} -> challenge_response(tx, msg, h)
        {:stale, h} -> challenge_response(tx, msg, h)
        :forbidden -> forbidden(tx, msg)
        :ok -> with_expires(tx, msg, from, aor, now_ms)
      end
    end
  end

  @impl true
  def init(_opts), do: {:ok, %{}}

  # новый запрос: заводим IST/NIST (§17.2) и разбираем по методу; 100 Trying
  # не шлём — REGISTER терминируется быстрее 200 мс (§17.2.1 требует его только
  # при отложенном ответе), и тушка UAC читает «следующий пакет», не фильтруя
  @impl true
  def handle_info({:sip_new_request, %Message{type: :request} = msg, from}, state) do
    {:ok, tx} =
      DynamicSupervisor.start_child(
        SipPbx.SIP.TransactionSupervisor,
        TxSupervisor.tx_child_spec(TxServer,
          transport: Transport,
          owner: self(),
          kind: :other,
          msg: msg,
          from: from
        )
      )

    case msg.method do
      "REGISTER" -> handle_register(msg, from, tx)
      "OPTIONS" -> respond(tx, msg, 200, "OK", [{"allow", @allow}])
      _ -> respond(tx, msg, 405, "Method Not Allowed", [{"allow", @allow}])
    end

    {:noreply, state}
  end

  # ретранслят финала и ACK держит IST; дубликат запроса Transport в IST уже
  # отдал транзакции — сюда он вернуться не может
  @impl true
  def handle_info({:tx_acked, _ref}, state), do: {:noreply, state}
  def handle_info({:tx_timeout_owner, _ref}, state), do: {:noreply, state}
  def handle_info({:tx_dup, _msg, _from}, state), do: {:noreply, state}

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------- REGISTER

  defp challenge_response(tx, msg, header) do
    respond(tx, msg, 401, "Unauthorized", [{"www-authenticate", header}])
  end

  # неверный пароль и неизвестный номер — одна формулировка (спека §5.4)
  defp forbidden(tx, msg) do
    Metrics.incr(:reg_fail)
    respond(tx, msg, 403, "Forbidden")
  end

  defp with_expires(tx, msg, from, aor, now_ms) do
    expires = requested_expires(msg)
    min = Application.fetch_env!(:sip_pbx, :min_expires)
    max = Application.fetch_env!(:sip_pbx, :max_expires)

    cond do
      expires == 0 ->
        Location.unregister(aor)
        respond(tx, msg, 200, "OK", contact_headers(msg, 0))

      expires < min ->
        respond(tx, msg, 423, "Interval Too Brief", [{"min-expires", to_string(min)}])

      true ->
        exp = min(expires, max)
        :ok = Location.register(aor, binding(msg, from, exp, now_ms), now_ms)
        Metrics.incr(:reg_ok)
        respond(tx, msg, 200, "OK", contact_headers(msg, exp) ++ [{"expires", to_string(exp)}])
    end
  end

  # заголовок Expires, иначе параметр expires первого Contact, иначе max_expires
  # (RFC 3261 §10.2.8); непарсящееся значение — тоже default
  defp requested_expires(msg) do
    raw =
      Message.header(msg, "expires") ||
        Message.header_param(msg, "contact", "expires")

    max = Application.fetch_env!(:sip_pbx, :max_expires)

    case raw && Integer.parse(raw) do
      {n, _} when n >= 0 -> n
      _ -> max
    end
  end

  defp binding(msg, from, exp, now_ms) do
    %{
      contact: Message.header(msg, "contact"),
      uri: Message.addr_uri(msg, "contact"),
      received: from,
      q: q_value(msg),
      expires_at: now_ms + exp * 1000
    }
  end

  defp q_value(msg) do
    case Message.header_param(msg, "contact", "q") do
      nil ->
        1.0

      v ->
        case Float.parse(v) do
          {q, _} -> q
          :error -> 1.0
        end
    end
  end

  # Contact ответа — исходный с переписанным expires (§10.2.8): параметр
  # из запроса снимаем и ставим согласованный
  defp contact_headers(msg, exp) do
    case Message.header(msg, "contact") do
      nil ->
        []

      raw ->
        rewritten =
          raw
          |> String.replace(~r/;\s*expires\s*=\s*[^;>]*/i, "")
          |> Kernel.<>(";expires=#{exp}")

        [{"contact", rewritten}]
    end
  end

  # --------------------------------------------------------------- прочее

  # §16.3: собственный sent-by в стеке Via — пакет вернулся к нам, зациклили.
  # Известных адресов у процесса нет (один стенд, адрес интерфейса не знает
  # никто), поэтому опознаём петлю по порту транспорта на loopback-хосте
  defp loop_detected?(msg) do
    port = Transport.local_port()

    Enum.any?(Message.headers(msg, "via"), fn via ->
      case via_sent_by(via) do
        {host, ^port} -> host in ["127.0.0.1", "localhost", "0.0.0.0"]
        _ -> false
      end
    end)
  end

  defp via_sent_by(via) do
    with [_, sent_by] <- Regex.run(~r/^SIP\/2\.0\/[A-Za-z0-9]+\s+([^;\s]+)/i, via),
         [host, port_s] <- String.split(sent_by, ":", parts: 2),
         {port, ""} <- Integer.parse(port_s) do
      {String.downcase(host), port}
    else
      _ -> :ignore
    end
  end

  # сборка ответа — Message.build_response (тот же хелпер, что в тестах
  # транзакций), extras — дописанные заголовки
  defp respond(tx, req, code, reason, extras \\ []) do
    resp =
      Enum.reduce(extras, Message.build_response(req, code, reason), fn {name, value}, acc ->
        Message.put_header(acc, name, value)
      end)

    TxServer.respond(tx, resp, true)
  end
end
