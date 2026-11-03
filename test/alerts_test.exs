defmodule SipPbx.AlertsTest do
  use ExUnit.Case, async: false
  alias SipPbx.{Alerts, PubSub}

  test "fire → активно → ack → может сработать снова; дребезг" do
    PubSub.subscribe()
    Alerts.fire(:auth_burst, %{ip: "1.2.3.4"})
    assert_receive {:alert_active, :auth_burst, %{ip: "1.2.3.4"}}, 500
    refute_receive {:alert_active, :auth_burst, _}, 50
    assert Enum.any?(Alerts.active(), &(&1.rule == :auth_burst))

    # повторный fire пока активно — нового события нет (дребезг)
    Alerts.fire(:auth_burst, %{ip: "1.2.3.4"})
    refute_receive {:alert_active, :auth_burst, _}, 50

    :ok = Alerts.ack(:auth_burst)
    assert Alerts.active() == []
  end

  test "бан-лист" do
    ip = {203, 0, 113, 7}
    refute Alerts.blocked?(ip)
    Alerts.block_ip(ip, 60_000)
    assert Alerts.blocked?(ip)
    assert [%{ip: ^ip}] = Alerts.blocked_list()
    :ok = Alerts.unblock(ip)
    refute Alerts.blocked?(ip)

    # уборка: block_ip поднимает алерт :blocked_ip и он остаётся активным —
    # без ack первый тест (assert active() == []) падает при перемешивании
    # порядка внутри кейса
    Alerts.ack(:blocked_ip)
  end

  test "правило beam_mem срабатывает на низком пороге" do
    Alerts.ack(:beam_mem)
    Application.put_env(:sip_pbx, :alert_rules, beam_mem_mb: 0)
    # тик проверки — раз в секунду
    Process.sleep(1300)
    assert Enum.any?(Alerts.active(), &(&1.rule == :beam_mem))
    Application.put_env(:sip_pbx, :alert_rules, beam_mem_mb: 512)

    # см. уборку в «бан-листе»: активный :beam_mem ломает инвариант первого теста
    Alerts.ack(:beam_mem)
  end
end
