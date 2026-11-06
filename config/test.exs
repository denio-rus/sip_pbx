import Config

# свои порты — тесты совместимы с запущенным ./run.sh (5060/8420)
config :sip_pbx, sip_port: 5160, web_port: 8421, t1_ms: 20, max_tx: 1000
