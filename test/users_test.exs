defmodule SipPbx.UsersTest do
  use ExUnit.Case, async: true

  alias SipPbx.Users

  test "справочник из конфига: 1001/1002/1003" do
    assert Enum.map(Users.all(), & &1.number) == ["1001", "1002", "1003"]
    assert Users.get("1001").password == "pass1001"
    assert Users.get("9999") == nil
  end
end
