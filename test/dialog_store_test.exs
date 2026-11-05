defmodule SipPbx.DialogStoreTest do
  use ExUnit.Case, async: false
  alias SipPbx.DialogStore
  alias SipPbx.DialogStore.Dialog

  # таблица :public на всё приложение (async: false), а assert all() == []
  # предполагает пустоту: чистим и до, и после — иначе соседний файл (Proxy,
  # Task 13) оставит свои диалоги
  setup do
    :ets.delete_all_objects(:sip_pbx_dialogs)
    on_exit(fn -> :ets.delete_all_objects(:sip_pbx_dialogs) end)
    :ok
  end

  defp dialog do
    %Dialog{
      call_id: "d1",
      state: :proceeding,
      a: %{
        number: "1001",
        uri: "sip:1001@pbx.local",
        contact: "<sip:a>",
        target: {{127, 0, 0, 1}, 5061},
        route_set: [],
        tag: "ta",
        resp_target: {{127, 0, 0, 1}, 5061}
      },
      b: nil,
      started_at: 0,
      active_at: nil
    }
  end

  test "put/get/update/delete + find_in_dialog по тегам" do
    DialogStore.put(dialog())
    assert %{state: :proceeding} = DialogStore.get("d1")
    DialogStore.update("d1", &%{&1 | state: :active, b: %{number: "1002"}})
    assert %{state: :active, b: %{number: "1002"}} = DialogStore.get("d1")

    assert {:a, %{tag: "ta"}} = DialogStore.find_in_dialog("d1", "ta", nil)
    DialogStore.delete("d1")
    assert DialogStore.get("d1") == nil
    assert DialogStore.all() == []
  end
end
