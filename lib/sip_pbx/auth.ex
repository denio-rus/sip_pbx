defmodule SipPbx.Auth do
  @moduledoc """
  Digest-аутентификация АТС (спека §5): выдача challenge, сверка `Authorization`
  (REGISTER) / `Proxy-Authorization` (прочее), nc-трекинг против replay и
  антибрутфорс. Nonce — stateless (`SipPbx.SIP.Digest.nonce/3`, HMAC привязан
  к IP, свежесть `@nonce_ttl_ms`), поэтому состояние процесса минимально:
  ETS `:sip_pbx_nc` (`{nonce, username} -> {nc, created_ms}`, приватная —
  пишется только через GenServer, строгий рост) и `:sip_pbx_auth_fails`
  (`ip -> {start_ms, count}`, `:public` — окно фейлов пишется с пути обработки
  напрямую, без GenServer'а).

  nc сохраняем при строгом росте НЕЗАВИСИМО от исхода digest-сверки: иначе
  replay одного пакета с перебором паролей обходил бы счётчик (разбор плана,
  ruling T10). Больше `@burst_limit` неуспехов с одного IP за `@burst_window_ms` —
  `SipPbx.Alerts.block_ip/2` на `@ban_ms` и алерт `:auth_burst`.

  Рестарт: `:one_for_one` поднимает процесс с пустыми таблицами — nc-счётчики
  обнуляются. Окно злоупотребления ограничено уже выданными nonce (свежесть
  привязана к IP), для учебного стенда принято; sweep снимает записи nc,
  пережившие актуальность своих nonce.
  """

  use GenServer

  alias SipPbx.{Alerts, Metrics, Users}
  alias SipPbx.SIP.{Digest, Message}

  # свежесть nonce (§5 спеки: 5 мин), порог/окно антибрутфорса и длительность бана
  @nonce_ttl_ms 300_000
  @burst_limit 10
  @burst_window_ms 30_000
  @ban_ms 900_000

  # запись nc не нужна после того, как её nonce гарантированно просрочен, —
  # sweep выкидывает записи старше TTL плюс запас на пересечение границ
  @sweep_ms 60_000

  @nc_table :sip_pbx_nc
  @fails_table :sip_pbx_auth_fails

  # аналог inet:ip_address(): Elixir не резолвит удалённые типы Erlang-модулей
  @type ip ::
          {0..255, 0..255, 0..255, 0..255}
          | {0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535, 0..65_535,
             0..65_535}

  @typedoc """
  Итог `verify/3`: `:ok` — digest сошёлся; `{:challenge, header}` — заголовка
  нет/битый/чужой nonce (401/407); `{:stale, header}` — nonce просрочен, повтор
  с тем же digest и `stale=true` (RFC 2617 §2.2); `:forbidden` — неверный
  digest, replay nc или неизвестный абонент (403, не подсказываем что именно).
  """
  @type verify_result ::
          :ok | :forbidden | {:challenge, String.t()} | {:stale, String.t()}

  @doc """
  Запустить хранилище nc и окон фейлов: создать обе ETS-таблицы и завести
  sweep переживших nonce записей каждые #{@sweep_ms} мс.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Выдать nonce и значение challenge-заголовка: `{nonce, header}`. Имя заголовка
  (`WWW-Authenticate` для REGISTER / `Proxy-Authenticate` для INVITE) выбирает
  вызывающий — схема одинаковая. `opts[:stale]` добавит `stale=true` (повтор
  после протухания nonce).
  """
  @spec challenge(ip(), keyword()) :: {String.t(), String.t()}
  def challenge(src_ip, opts \\ []) do
    nonce = Digest.nonce(secret(), src_ip, System.system_time(:millisecond))
    {nonce, Digest.challenge_header(realm(), nonce, opaque(), opts)}
  end

  @doc """
  Сверить аутентификацию запроса: по методу берётся `Authorization` (REGISTER)
  или `Proxy-Authorization` (прочее, 407-ветка §22.2). Порядок: nonce (подпись,
  IP, свежесть) → строгий рост nc → сверка digest с паролем `Users`; любой
  неуспех, кроме challenge/stale, помечает `:auth_fail` и участвует в окне
  антибрутфорса. `opts[:now_ms]` — системное время в мс (для тестов).

  Выполняется в процессе вызывающего; bump nc — синхронный `call` на `Auth`,
  поэтому из самого процесса `Auth` функцию звать нельзя (взаимоблок).
  """
  @spec verify(Message.t(), ip(), keyword()) :: verify_result()
  def verify(%Message{} = msg, src_ip, opts \\ []) do
    now_ms = Keyword.get(opts, :now_ms, System.system_time(:millisecond))
    header_name = if msg.method == "REGISTER", do: "authorization", else: "proxy-authorization"

    with value when is_binary(value) <- Message.header(msg, header_name),
         {:ok, auth} <- Digest.parse_auth(value) do
      check_auth(auth, msg.method, src_ip, now_ms)
    else
      _ -> {:challenge, header(src_ip, [])}
    end
  end

  @impl true
  def init(_opts) do
    @nc_table = :ets.new(@nc_table, [:set, :protected, :named_table])

    @fails_table =
      :ets.new(@fails_table, [:set, :public, :named_table, read_concurrency: true])

    schedule_sweep()
    {:ok, %{}}
  end

  # строгий рост nc на пару (nonce, username): не больше сохранённого — replay,
  # больше — сохраняем сразу, до и независимо от исхода digest-сверки (ruling T10)
  @impl true
  def handle_call({:nc_bump, key, nc}, _from, state) do
    case :ets.lookup(@nc_table, key) do
      [{^key, {saved, _created}}] when nc <= saved ->
        {:reply, :replay, state}

      _ ->
        :ets.insert(@nc_table, {key, {nc, System.system_time(:millisecond)}})
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_info(:sweep, state) do
    horizon = System.system_time(:millisecond) - (@nonce_ttl_ms + @sweep_ms)

    @nc_table
    |> :ets.tab2list()
    |> Enum.each(fn {key, {_nc, created}} ->
      unless created > horizon, do: :ets.delete(@nc_table, key)
    end)

    schedule_sweep()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # неизвестный абонент не получает подсказки даже через стадию nonce — сразу
  # 403 (спека §5.4); nonce за ним не проверяем: пароль всё равно не сверить
  defp check_auth(auth, method, src_ip, now_ms) do
    case Users.get(auth["username"]) do
      nil ->
        record_fail(src_ip, now_ms)
        :forbidden

      %{password: password} ->
        auth
        |> Digest.verify(password, method, nonce_checker(src_ip, now_ms))
        |> reply(src_ip, now_ms)
    end
  end

  defp reply(:ok, _src_ip, _now_ms), do: :ok
  defp reply({:error, :stale}, src_ip, _now_ms), do: {:stale, header(src_ip, stale: true)}
  defp reply({:error, :bad_nonce}, src_ip, _now_ms), do: {:challenge, header(src_ip, [])}

  # :bad_digest и пропущенный callback'ом :replay — одинаковая судьба: 403
  defp reply({:error, _other}, src_ip, now_ms) do
    record_fail(src_ip, now_ms)
    :forbidden
  end

  # callback для Digest.verify/4: stateless-проверка nonce, затем nc; любой
  # non-:ok Digest.verify пропускает наружу как есть
  defp nonce_checker(src_ip, now_ms) do
    fn auth ->
      case Digest.check_nonce(secret(), src_ip, auth["nonce"], now_ms, @nonce_ttl_ms) do
        :ok -> check_nc(auth, auth["nonce"])
        {:error, why} -> {:error, map_nonce_error(why)}
      end
    end
  end

  defp map_nonce_error(:stale), do: :stale
  defp map_nonce_error(:bad), do: :bad_nonce

  # nc обязателен только при qop (классическая форма RFC 2069 — без него);
  # основание 16 — форма nc по RFC 2617 §3.2.2 («8DIGIT HEX»), битый nc —
  # битый challenge-ответ, та же судьба, что чужой nonce
  defp check_nc(%{"qop" => _} = auth, nonce) do
    case Integer.parse(to_string(auth["nc"]), 16) do
      {nc, ""} ->
        case GenServer.call(__MODULE__, {:nc_bump, {nonce, auth["username"]}, nc}) do
          :ok -> :ok
          :replay -> {:error, :replay}
        end

      _ ->
        {:error, :bad_nonce}
    end
  end

  defp check_nc(_auth, _nonce), do: :ok

  # окно фейлов на IP: {start_ms, count}; пишется с пути обработки напрямую в
  # :public таблицу, без GenServer'а. Сброс устаревшего окна не атомарен с
  # инкрементом — для порога «>N за окно» допустимо (максимум на одно событие
  # окна раньше/позже, не точнее антибрутфорс не делает)
  defp record_fail(ip, now_ms) do
    Metrics.incr(:auth_fail)

    case :ets.lookup(@fails_table, ip) do
      [{^ip, start_ms, _count}] when now_ms - start_ms < @burst_window_ms ->
        bump(ip, :ets.update_counter(@fails_table, ip, {3, 1}))

      _ ->
        # окна нет или оно устарело — заводим новое; если параллельный писатель
        # опередил, insert_new сохранит его окно, а инкремент попадёт в него
        :ets.insert_new(@fails_table, {ip, now_ms, 0})
        bump(ip, :ets.update_counter(@fails_table, ip, {3, 1}))
    end
  end

  defp bump(_ip, count) when count <= @burst_limit, do: :ok

  defp bump(ip, _count) do
    # окно чистим, иначе каждое следующее >10 повторяло бы бан и алерт;
    # дребезг Alerts гасит повторные :auth_burst, block_ip продлевает бан
    :ets.delete(@fails_table, ip)
    Alerts.block_ip(ip, @ban_ms)
    Alerts.fire(:auth_burst, %{ip: ip |> :inet.ntoa() |> to_string()})
    :ok
  end

  defp header(src_ip, opts), do: elem(challenge(src_ip, opts), 1)

  defp realm, do: Application.fetch_env!(:sip_pbx, :realm)
  defp secret, do: Application.fetch_env!(:sip_pbx, :auth_secret)

  # стабильный на секрет opaque (RFC 2617 §2.2): клиент вернёт его как есть,
  # привязки к nonce тут нет
  defp opaque,
    do: Base.encode16(:crypto.hash(:sha256, secret() <> "opaque"), case: :lower)

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_ms)
end
