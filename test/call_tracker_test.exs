defmodule SipPbx.CallTrackerTest do
  use ExUnit.Case, async: false
  alias SipPbx.{CallTracker, PubSub}

  # кольцо :sip_pbx_calls — глобальное состояние приложения (async: false),
  # [row] = list() предполагает пустую таблицу: чистим и до, и после
  setup do
    :ets.delete_all_objects(:sip_pbx_calls)
    on_exit(fn -> :ets.delete_all_objects(:sip_pbx_calls) end)
    :ok
  end

  test "begin/set_state/finish: тайминги плеч и событие call_event" do
    PubSub.subscribe()
    CallTracker.begin("c1", "1001", "1002")
    CallTracker.set_state("c1", :a, :trying, 0)
    CallTracker.set_state("c1", :b, :ringing, 100)
    CallTracker.finish("c1", :hangup, nil)

    assert_receive {:call_state, "c1", :b, :ringing}, 500
    [row] = CallTracker.list()
    assert row.caller == "1001" and row.callee == "1002"
    assert row.status == :hangup
    assert %{trying: 0} = Enum.find(row.legs, &(&1.name == :a)).states
  end
end
