defmodule SipPbx.Users do
  @moduledoc """
  Статический справочник абонентов (`config/users.exs`). Hot-reload абонентов
  нет — по спецификации это вне v1.
  """

  @type t :: %{number: String.t(), password: String.t(), name: String.t()}

  @doc "Все абоненты справочника."
  @spec all() :: [t()]
  def all, do: Application.fetch_env!(:sip_pbx, :users)

  @doc "Абонент по номеру, `nil` если номера нет в справочнике."
  @spec get(String.t()) :: t() | nil
  def get(number), do: Enum.find(all(), &(&1.number == number))
end
