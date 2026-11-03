# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Ambient expense-approval agent implemented as an ADK 2.0 graph workflow.

Flow:
1. Expense report arrives as a JSON event (Pub/Sub push, webhook, or direct invocation).
2. Routing node applies deterministic Python logic:
   - Under $100 -> Instant auto-approval (zero LLM calls).
   - $100 or more -> Routed to Security Checkpoint.
3. Security Checkpoint:
   - Scrubs SSNs and Credit Card numbers from the description.
   - Inspects for prompt-injection attempts.
   - If prompt injection detected: Bypasses LLM reviewer entirely and routes
     straight to human review with a security alert.
   - If clean: Routes to LLM reviewer for qualitative risk assessment.
4. LLM reviewer evaluates policy risks on sanitized data.
5. Workflow pauses via RequestInput (HITL) for human manager approval/rejection.
6. On resumption, final decision is logged and returned.
"""

import base64
import json
import os
import re
from typing import Any

from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.apps import App
from google.adk.events import Event, EventActions, RequestInput
from google.adk.workflow import Workflow
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ExpenseReport(BaseModel):
    """Structured expense report received from the incoming event."""

    amount: float = Field(description="Expense amount in USD")
    submitter: str = Field(description="Email or user ID of submitter")
    category: str = Field(description="Category (travel, meals, hardware, etc.)")
    description: str = Field(description="Description of the purchase")
    date: str = Field(description="Date of the expense in YYYY-MM-DD format")


class RiskAnalysis(BaseModel):
    """Structured risk judgment produced by the LLM reviewer or security checkpoint."""

    risk_level: str = Field(description="Assessed risk level: low, medium, or high")
    risk_factors: list[str] = Field(
        default_factory=list,
        description="Identified risk factors (e.g. policy violations, prompt injection, unusual cost)",
    )
    recommendation: str = Field(
        description="Recommended action: approve, reject, or escalate"
    )
    summary: str = Field(
        description="Concise summary explaining the risk assessment to the human approver"
    )


# ---------------------------------------------------------------------------
# Security & Sanitization Patterns
# ---------------------------------------------------------------------------

# US Social Security Number pattern (e.g. 123-45-6789, 123 45 6789)
SSN_PATTERN = re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b")

# Credit Card pattern (Visa, MasterCard, Amex, Discover, 13-16 digit grouped/raw)
CC_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
    r"5[1-5][0-9]{14}|"  # MasterCard
    r"3[47][0-9]{13}|"  # American Express
    r"6(?:011|5[0-9]{2})[0-9]{12}|"  # Discover
    r"(?:\d{4}[- ]?){3}\d{4})\b"  # Generic 16-digit formatted
)

# Common prompt injection signatures and instruction-override heuristics
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\b(system\s+prompt|system\s+role)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(an?|in)\b"),
    re.compile(r"(?i)\bjailbreak\b"),
    re.compile(r"(?i)\b(dan|developer)\s+mode\b"),
    re.compile(r"(?i)\bnew\s+instruction[s]?\s*:"),
    re.compile(r"(?i)\bforget\s+(everything|your\s+instructions)\b"),
    re.compile(r"(?i)\badmin\s+override\b"),
    re.compile(r"(?i)\bauto-?approve\s+this\s+expense\b"),
]


def scrub_pii(text: str) -> str:
    """Scrub SSNs and Credit Card numbers from text."""
    if not text:
        return text
    scrubbed = SSN_PATTERN.sub("[REDACTED_SSN]", text)
    scrubbed = CC_PATTERN.sub("[REDACTED_CREDIT_CARD]", scrubbed)
    return scrubbed


def detect_prompt_injection(text: str) -> str | None:
    """Detect prompt injection patterns in text.

    Returns the matching pattern or description if found, else None.
    """
    if not text:
        return None
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


# ---------------------------------------------------------------------------
# Workflow Nodes
# ---------------------------------------------------------------------------

REVIEW_THRESHOLD_USD = 100.0


def parse_expense_event(node_input: Any) -> Event:
    """Parse incoming JSON or dict payload into validated ExpenseReport."""
    data = node_input

    # Parse JSON string if input is a string or types.Content text
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as err:
            return Event(output={"error": f"Invalid JSON input: {err}"})
    elif hasattr(data, "parts") and data.parts:
        text = "".join(part.text for part in data.parts if getattr(part, "text", None))
        try:
            data = json.loads(text)
        except json.JSONDecodeError as err:
            return Event(output={"error": f"Invalid JSON content text: {err}"})

    # Unwrap Pub/Sub envelope if present
    if isinstance(data, dict):
        if (
            "message" in data
            and isinstance(data["message"], dict)
            and "data" in data["message"]
        ):
            raw_data = data["message"]["data"]
            if isinstance(raw_data, str):
                try:
                    decoded = base64.b64decode(raw_data).decode("utf-8")
                    data = json.loads(decoded)
                except Exception:
                    pass
        elif "data" in data and isinstance(data["data"], dict):
            data = data["data"]

    expense = ExpenseReport(
        amount=float(data.get("amount", 0.0)),
        submitter=str(data.get("submitter", "unknown")),
        category=str(data.get("category", "other")),
        description=str(data.get("description", "")),
        date=str(data.get("date", "")),
    )
    return Event(output=expense.model_dump())


def route_by_amount(node_input: dict[str, Any], ctx: Context) -> Event:
    """Pure Python deterministic routing based on the $100 threshold.

    - Under $100 (< $100.00): Auto-approves instantly without invoking an LLM.
    - $100 or more (>= $100.00): Routes to the Security Checkpoint.
    """
    ctx.state["expense_data"] = node_input
    amount = float(node_input.get("amount", 0.0))

    if amount >= REVIEW_THRESHOLD_USD:
        return Event(actions=EventActions(route="NEEDS_REVIEW"), output=node_input)
    return Event(actions=EventActions(route="AUTO_APPROVE"), output=node_input)


def auto_approve(node_input: dict[str, Any], ctx: Context) -> Event:
    """Auto-approve expenses under $100 without LLM involvement."""
    result = {
        "status": "approved",
        "action": "auto_approved",
        "reason": f"Amount ${node_input['amount']:.2f} is under ${REVIEW_THRESHOLD_USD:.2f} threshold",
        "expense": node_input,
    }
    return Event(output=result)


def security_checkpoint(node_input: dict[str, Any], ctx: Context) -> Event:
    """Pre-LLM Security Checkpoint for high-value expenses.

    1. Scrubs SSNs and Credit Card numbers from the description.
    2. Inspects for prompt-injection attempts.
       - If detected: Flags alert, populates security risk summary, and routes
         straight to human review ('SUSPICIOUS_PROMPT'), bypassing LLM entirely.
       - If clean: Routes to LLM reviewer ('SAFE_TO_REVIEW').
    """
    sanitized = dict(node_input)
    description = sanitized.get("description", "")

    # 1. Scrub SSNs and Credit Card numbers
    scrubbed_desc = scrub_pii(description)
    sanitized["description"] = scrubbed_desc
    ctx.state["expense_data"] = sanitized

    # 2. Check for prompt injection attempts in description or other fields
    injection_match = detect_prompt_injection(description)

    if injection_match:
        alert_msg = f"Prompt injection pattern detected: '{injection_match}'"
        ctx.state["security_alert"] = alert_msg

        # Synthetic high-risk assessment bypassing the LLM
        ctx.state["risk_analysis"] = RiskAnalysis(
            risk_level="high",
            risk_factors=["Prompt injection attempt detected in expense description"],
            recommendation="reject",
            summary=(
                f"SECURITY WARNING: {alert_msg}. The LLM reviewer was bypassed "
                "to prevent prompt manipulation. Escalated immediately for human inspection."
            ),
        ).model_dump()

        return Event(actions=EventActions(route="SUSPICIOUS_PROMPT"), output=sanitized)

    return Event(actions=EventActions(route="SAFE_TO_REVIEW"), output=sanitized)


# The LLM reviewer is invoked ONLY for qualitative risk judgment on clean expenses >= $100
risk_reviewer = LlmAgent(
    name="risk_reviewer",
    model=os.getenv("MODEL_NAME", "gemini-3.5-flash"),
    instruction="""You are an expert expense risk reviewer for corporate expense reports of $100 or more.
Analyze the expense for potential financial, compliance, and policy risks:
1. Category-amount alignment (e.g. unusually high meal costs, inappropriate categories).
2. Clarity of description (e.g. vague items like 'miscellaneous', round numbers, missing vendor details).
3. Value threshold risk (high-dollar amounts requiring executive justification).

Produce a structured RiskAnalysis with risk_level (low/medium/high), identified risk factors, a recommendation, and a concise summary.""",
    output_schema=RiskAnalysis,
    output_key="risk_analysis",
)


def pause_for_human_approval(node_input: Any, ctx: Context):
    """Pause workflow execution and request manager approval (HITL).

    Surfaces the expense, LLM risk assessment (or security alert), and waits
    for a human to resume the session with an approve/reject decision.
    """
    expense = ctx.state.get("expense_data", {})
    risk = ctx.state.get("risk_analysis", node_input)
    alert = ctx.state.get("security_alert")

    message = (
        f"Expense of ${expense.get('amount', 0.0):.2f} from "
        f"{expense.get('submitter', 'unknown')} requires human approval."
    )
    if alert:
        message = f"🚨 [SECURITY ALERT: {alert}] " + message

    yield RequestInput(
        interrupt_id="manager_approval",
        message=message,
        payload={
            "expense": expense,
            "risk_assessment": risk,
            "security_alert": alert,
        },
    )


def process_human_decision(node_input: Any, ctx: Context) -> Event:
    """Process human reviewer decision upon workflow resumption."""
    decision = "unknown"
    notes = ""

    if isinstance(node_input, dict):
        decision = node_input.get("decision", "unknown").lower()
        notes = node_input.get("notes", "")
    elif isinstance(node_input, str):
        decision = "approve" if "approve" in node_input.lower() else "reject"

    approved = decision == "approve"
    status = "approved" if approved else "rejected"
    expense = ctx.state.get("expense_data", {})
    risk = ctx.state.get("risk_analysis", {})

    result = {
        "status": status,
        "action": "human_reviewed",
        "decision": decision,
        "notes": notes,
        "expense": expense,
        "risk_assessment": risk,
        "security_alert": ctx.state.get("security_alert"),
    }
    return Event(output=result)


# ---------------------------------------------------------------------------
# Graph Definition (ADK 2.0 Workflow)
# ---------------------------------------------------------------------------

root_agent = Workflow(
    name="ambient_expense_agent_test",
    description="Ambient expense approval agent with deterministic code routing, security checkpoint, and LLM risk review",
    edges=[
        # 1. Entry point -> Parser -> Threshold Router
        ("START", parse_expense_event, route_by_amount),
        # 2. Branch: < $100 auto-approves instantly; >= $100 goes to Security Checkpoint
        (
            route_by_amount,
            {
                "AUTO_APPROVE": auto_approve,
                "NEEDS_REVIEW": security_checkpoint,
            },
        ),
        # 3. Security Checkpoint:
        #    - Suspicious prompt -> bypasses model, routes straight to HITL pause
        #    - Safe to review -> routes to LLM risk reviewer
        (
            security_checkpoint,
            {
                "SUSPICIOUS_PROMPT": pause_for_human_approval,
                "SAFE_TO_REVIEW": risk_reviewer,
            },
        ),
        # 4. LLM reviewer -> HITL pause -> Human decision
        (risk_reviewer, pause_for_human_approval),
        (pause_for_human_approval, process_human_decision),
    ],
)

app = App(
    name="ambient_expense_agent_test",
    root_agent=root_agent,
)
