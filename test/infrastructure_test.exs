defmodule InfrastructureTest do
  use ExUnit.Case, async: false

  alias SipPbx.{LogBuffer, Metrics, PubSub}

  test "журнал: порядок и live-событие в pubsub" do
    LogBuffer.add(:in, "INVITE sip:1002@pbx", "INVITE ...")
    LogBuffer.add(:info, "маршрут найден", "маршрут найден")
    log = LogBuffer.all()

    # карта-паттерн матчит подмножество ключей — полная запись с raw/ts тоже подходит
    assert [%{dir: :in, first: "INVITE sip:1002@pbx"}, %{dir: :info}] =
             Enum.slice(log, -2..-1)

    PubSub.subscribe()
    PubSub.broadcast(:sip_log, {:sip_log, %{dir: :out, first: "200 OK", raw: "..."}})
    assert_receive {:sip_log, %{first: "200 OK"}}, 500
  end

  test "кольцо: старые вытесняются" do
    for i <- 1..3000, do: LogBuffer.add(:info, "e#{i}", "e#{i}")
    log = LogBuffer.all()
    assert length(log) == 2000
    assert hd(log).first == "e1001"
  end

  test "счётчики и ряд сэмплера" do
    Metrics.incr(:pkt_in, 3)
    assert Metrics.get(:pkt_in) >= 3
    Metrics.gauge(:dummy_gauge, fn -> 42 end)
    # тик сэмплера — раз в секунду
    Process.sleep(1300)
    snap = Metrics.snapshot()
    assert snap.counters.pkt_in >= 3
    assert [{_ts, 42} | _] = Enum.reverse(snap.series.dummy_gauge)
  end
end
