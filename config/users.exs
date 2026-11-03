import Config

config :sip_pbx,
  users: [
    %{number: "1001", password: "pass1001", name: "Алиса"},
    %{number: "1002", password: "pass1002", name: "Боб"},
    # 1003 — заведомо незанятый: на него проверяем 404
    %{number: "1003", password: "pass1003", name: "Карол"}
  ]
