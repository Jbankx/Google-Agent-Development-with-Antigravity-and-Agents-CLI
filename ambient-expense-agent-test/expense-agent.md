Feature: Expense Report Processing

  Scenario: Low-value expense auto-approval
    Given an expense report with amount: 45
    When the agent processes the report
    Then it auto-approves with no LLM call

  Scenario: High-value expense with PII in the description
    Given an expense report with amount: 250 and an SSN and Credit Card in the description
    When the agent processes the report
    Then it redacts the SSN and Credit Card before the LLM reviewer sees it
    And it routes to human approval after the LLM review

  Scenario: High-value expense with prompt injection attempt
    Given an expense report with amount: 250 and a prompt-injection attempt in the description
    When the agent processes the report
    Then it bypasses the LLM reviewer entirely
    And it routes straight to human review with a security alert
