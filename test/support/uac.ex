defmodule SipPbxTest.UAC do
  @moduledoc """
  Низкоуровневый тестовый UAC: пассивный UDP-сокет и три примитива — открыть,
  отправить сырые байты, принять и распарсить следующий SIP-пакет.
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

  @doc "Отправить сырые байты в `target` — `{ip, port}`."
  @spec send(sock(), {tuple(), :inet.port_number()}, iodata()) :: :ok | {:error, term()}
  def send(sock, {ip, port}, data) do
    :gen_udp.send(sock, ip, port, data)
  end

  @doc """
  Ждать следующий пакет до `timeout` мс и разобрать его; таймаут —
  `{:error, :timeout}` (как его отдаёт `:gen_udp.recv/3`).
  """
  @spec recv(sock(), timeout()) :: {:ok, Message.t()} | {:error, term()}
  def recv(sock, timeout) do
    case :gen_udp.recv(sock, 0, timeout) do
      {:ok, {_ip, _port, data}} -> Message.parse(data)
      {:error, reason} -> {:error, reason}
    end
  end
end
