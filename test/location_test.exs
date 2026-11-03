defmodule SipPbx.LocationTest do
  use ExUnit.Case, async: false
  alias SipPbx.Location

  test "register/lookup/expiry/unregister" do
    Location.register(
      "sip:1001@pbx",
      %{
        contact: "<sip:a@1.2.3.4:5060>",
        uri: "sip:a@1.2.3.4:5060",
        received: {{1, 2, 3, 4}, 5060},
        q: 1.0,
        expires_at: 1_000
      },
      0
    )

    assert %{received: {{1, 2, 3, 4}, 5060}} = Location.lookup("sip:1001@pbx", 500)
    assert Location.lookup("sip:1001@pbx", 1_500) == nil

    Location.register(
      "sip:1001@pbx",
      %{
        contact: "c2",
        uri: "sip:a@1.2.3.4:5060",
        received: {{1, 2, 3, 4}, 5060},
        q: 1.0,
        expires_at: 5_000
      },
      1_600
    )

    Location.unregister("sip:1001@pbx")
    assert Location.lookup("sip:1001@pbx", 2_000) == nil
    assert Location.list(2_000) == %{}
  end

  # Регресс на правку ревью: REGISTER с меньшим Expires (укорочение живого
  # binding'а, например со второго девайса на том же AOR) обязан побеждать —
  # иначе Registrar отвечает 200 OK, а маршрутизация идёт по старому контакту.
  test "повторный REGISTER перезаписывает binding — последний побеждает" do
    Location.register(
      "sip:1005@pbx.local",
      %{
        contact: "long",
        uri: "sip:e@h:5060",
        received: {{1, 2, 3, 4}, 5060},
        q: 1.0,
        expires_at: 5_000
      },
      1_600
    )

    Location.register(
      "sip:1005@pbx.local",
      %{
        contact: "short",
        uri: "sip:f@h:5061",
        received: {{1, 2, 3, 4}, 5061},
        q: 1.0,
        expires_at: 3_000
      },
      1_700
    )

    assert %{contact: "short", expires_at: 3_000} = Location.lookup("sip:1005@pbx.local", 1_800)
    Location.unregister("sip:1005@pbx.local")
  end

  # Порядок тестов внутри файла рандомизируется сидом, поэтому тест убирает за
  # собой все записи — иначе соседний `list/1` видел бы мусор.
  test "list режет истёкшие; drop_number снимает по номеру, не трогая соседей" do
    Location.register(
      "sip:1002@pbx.local",
      %{
        contact: "c1",
        uri: "sip:b@h:5060",
        received: {{1, 2, 3, 4}, 5060},
        q: 1.0,
        expires_at: 4_000
      },
      0
    )

    Location.register(
      "sip:1002@other.realm",
      %{
        contact: "c2",
        uri: "sip:b@h:5060",
        received: {{1, 2, 3, 4}, 5061},
        q: 1.0,
        expires_at: 4_000
      },
      0
    )

    Location.register(
      "sip:1003@pbx.local",
      %{
        contact: "c3",
        uri: "sip:c@h:5060",
        received: {{1, 2, 3, 4}, 5062},
        q: 1.0,
        expires_at: 4_000
      },
      0
    )

    Location.register(
      "sip:1099@pbx.local",
      %{
        contact: "c9",
        uri: "sip:d@h:5060",
        received: {{1, 2, 3, 4}, 5063},
        q: 1.0,
        expires_at: 2_000
      },
      0
    )

    assert Enum.sort(Map.keys(Location.list(3_000))) == [
             "sip:1002@other.realm",
             "sip:1002@pbx.local",
             "sip:1003@pbx.local"
           ]

    # realm в AOR — хост из Request-URI, поэтому снимаем по префиксу номера:
    # оба realm-адреса 1002 уходят, «10» не задевает 1002/1003/1099.
    assert Location.drop_number("1002") == 2
    assert Location.lookup("sip:1002@pbx.local", 1_000) == nil
    assert Location.drop_number("10") == 0
    assert %{contact: "c3"} = Location.lookup("sip:1003@pbx.local", 1_000)

    Location.drop_number("1003")
    Location.drop_number("1099")
    assert Location.list(3_000) == %{}
  end
end
