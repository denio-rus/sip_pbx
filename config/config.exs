import Config

config :sip_pbx,
  sip_port: String.to_integer(System.get_env("SIP_PBX_SIP_PORT", "5060")),
  web_port: String.to_integer(System.get_env("SIP_PBX_WEB_PORT", "8420")),
  t1_ms: 500,
  realm: "pbx.local",
  auth_secret: System.get_env("SIP_PBX_AUTH_SECRET", "change-me-learning-stand"),
  min_expires: 60,
  max_expires: 3600,
  # лимит живых транзакционных ключей: выше — 503 (спека §6)
  max_tx: 200,
  # пороги алерт-правил SipPbx.Alerts (мин. выборка tx_timeout_rate — константа в модуле)
  alert_rules: [
    beam_mem_mb: 512,
    reg_failure_window_s: 60,
    reg_failure_n: 5,
    tx_timeout_window_s: 30,
    tx_timeout_pct: 30,
    retrans_per_s: 20
  ]

import_config "#{config_env()}.exs"
import_config "users.exs"
