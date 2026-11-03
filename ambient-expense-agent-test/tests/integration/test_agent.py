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

import json

import pytest
from google.adk.runners import InMemoryRunner
from google.genai import types

from app.agent import app


@pytest.mark.asyncio
async def test_auto_approve_under_100() -> None:
    """Low-value expenses (< $100) must auto-approve instantly with zero LLM calls."""
    runner = InMemoryRunner(app=app)
    session = await runner.session_service.create_session(
        app_name=app.name, user_id="test_user"
    )

    payload = json.dumps(
        {
            "amount": 42.50,
            "submitter": "alice@company.com",
            "category": "meals",
            "description": "Lunch meeting with prospect",
            "date": "2026-11-03",
        }
    )

    events = []
    async for event in runner.run_async(
        user_id="test_user",
        session_id=session.id,
        new_message=types.Content(
            role="user", parts=[types.Part.from_text(text=payload)]
        ),
    ):
        events.append(event)

    outputs = [e.output for e in events if e.output and "status" in e.output]
    assert len(outputs) == 1
    assert outputs[0]["status"] == "approved"
    assert outputs[0]["action"] == "auto_approved"
    assert outputs[0]["expense"]["amount"] == 42.50
