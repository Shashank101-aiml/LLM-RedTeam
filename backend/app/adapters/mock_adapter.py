"""
MockTargetAdapter implementation.
"""

from app.adapters.base import TargetAdapter, TargetResponse
from app.evaluation.context import ExecutionContext
from app.targets.mock_target import MockTarget


class MockTargetAdapter(TargetAdapter):
    """Adapter for in-memory MockTarget (secure or vulnerable)."""

    def __init__(self, mode: str = "secure", name: str = "Deterministic Mock Target"):
        super().__init__(name=name, endpoint_url="http://localhost:8000/mock", safe_mode=True)
        self.mock_target = MockTarget(mode=mode)

    async def execute(self, context: ExecutionContext) -> TargetResponse:
        self.validate_target_safety()
        tc = context.test_case

        result = self.mock_target.process(
            prompt=tc.input_prompt,
            system_prompt=tc.system_prompt,
            retrieved_context=tc.retrieved_context,
            tenant_id=tc.tenant_id,
            user_role=tc.user_role,
            target_tool_name=tc.target_tool_name,
        )

        return TargetResponse(
            output_text=result["output"],
            tool_calls_attempted=result.get("tool_calls", []),
            duration_ms=result.get("duration_ms", 0.0),
            status_code=200,
            raw_response=result,
        )
