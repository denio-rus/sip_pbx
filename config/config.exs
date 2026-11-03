import Config

config :sip_pbx,
  sip_port: String.to_integer(System.get_env("SIP_PBX_SIP_PORT", "5060")),
  web_port: String.to_integer(System.get_env("SIP_PBX_WEB_PORT", "8420")),
  t1_ms: 500,
  realm: "pbx.local",
  auth_secret: System.get_env("SIP_PBX_AUTH_SECRET", "change-me-learning-stand"),
  min_expires: 60,
  max_expires: 3600

import_config "#{config_env()}.exs"
import_config "users.exs"
