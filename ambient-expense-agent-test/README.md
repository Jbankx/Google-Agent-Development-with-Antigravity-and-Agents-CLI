# Ambient Expense Agent

An ambient expense-approval workflow built with Google's **Agent Development Kit (ADK 2.0)**. The agent automates expense reviews using deterministic code routing, automated PII scrubbing, prompt-injection defense, qualitative LLM risk assessment with Gemini, and human-in-the-loop (HITL) manager approval.

---

## Architecture & Workflow

```text
[Expense Event]
       │
       ▼
 [Parse Expense]
       │
       ▼
 [Amount Router] ── (< $100) ──► [Auto-Approve] ──► (Approved)
       │
   (>= $100)
       ▼
[Security Checkpoint]
   ├── PII Scrubbing (Redacts SSNs & Credit Cards)
   └── Prompt Injection Check
       │
       ├── (Suspicious) ──► [Flag Alert & Bypass LLM] ──┐
       │                                                 │
       └── (Clean) ──► [LLM Risk Reviewer (Gemini)] ────┼──► [Human Approval (HITL)] ──► [Final Decision]
```

### Key Capabilities

- **Deterministic Auto-Approval (< $100)**: Low-value expenses auto-approve instantly in pure Python with zero LLM calls, saving latency and cost.
- **Pre-LLM Security Checkpoint**:
  - **PII Scrubbing**: Automatically detects and redacts US Social Security Numbers (`SSN`) and Credit Card numbers from expense descriptions.
  - **Prompt-Injection Defense**: Detects instruction-override attempts (e.g., `"ignore previous instructions"`). Suspicious payloads bypass the LLM entirely, generate an immediate security alert, and escalate directly to human review.
- **LLM Risk Assessment**: Clean expenses of $100 or more are evaluated by Gemini (`gemini-3.5-flash`) for category alignment, policy compliance, and vague descriptions.
- **Human-in-the-Loop (HITL)**: Pauses execution via ADK's `RequestInput` (`manager_approval`) and presents the sanitized expense, risk analysis, and security alerts for human sign-off.

---

## Project Structure

```text
ambient-expense-agent-test/
├── app/
│   ├── agent.py               # ADK 2.0 workflow graph, security checkpoint, and LLM agent
│   └── fast_api_app.py        # FastAPI server backend
├── tests/
│   ├── unit/                  # Tests for routing, PII scrubbing, injection detection & HITL
│   ├── integration/           # End-to-end workflow runner tests
│   └── eval/                  # Agent evaluation datasets and quality metrics
├── pyproject.toml             # Python dependencies and tool configurations
└── README.md                  # Project documentation
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [agents-cli](https://cloud.google.com/) (`uv tool install google-agents-cli`)

### 1. Install Dependencies

```bash
uv sync
```
*Or using `agents-cli`:*
```bash
agents-cli install
```

### 2. Environment Configuration

Create a `.env` file in the project root (see `.env.example`):

```bash
MODEL_NAME=gemini-3.5-flash
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=<your-gcp-project-id>
GOOGLE_CLOUD_LOCATION=us-central1
```

### 3. Run Tests

Run the test suite with pytest:

```bash
uv run pytest tests/unit tests/integration
```

### 4. Local Interactive Playground

Launch the local web-based playground to test the workflow interactively:

```bash
agents-cli playground
```

---

## Useful Commands

| Task | Command |
| :--- | :--- |
| **Install dependencies** | `agents-cli install` / `uv sync` |
| **Run tests** | `uv run pytest tests/unit tests/integration` |
| **Code linting** | `agents-cli lint` / `uv run ruff check .` |
| **Local playground** | `agents-cli playground` |
| **Run evaluations** | `agents-cli eval run` |
| **Deploy agent** | `agents-cli deploy` |
