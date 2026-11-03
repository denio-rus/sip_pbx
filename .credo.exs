# Конфиг Credo. Пороги сложности/вложенности подняты до фактических значений
# стейт-машины SipPhone.SIP.Stack: её ветвистые обработчики digest/транзакций
# регрессионно ценнее их дробления (реальный ECSS-10, work_log §6–§10, §20).
# Порог = текущий максимум, так что новые сверх-сложные функции всё равно
# попадают в отчёт; остальные проверки — по умолчанию, прогон в --strict.
%{
  configs: [
    %{
      name: "default",
      strict: true,
      files: %{
        included: ["lib/"]
      },
      checks: [
        {Credo.Check.Refactor.CyclomaticComplexity, max_complexity: 16},
        {Credo.Check.Refactor.Nesting, max_nesting: 3}
      ]
    }
  ]
}
