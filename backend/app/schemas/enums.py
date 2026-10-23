"""
Domain Enumerations for LLM Sentinel.
"""

from enum import Enum


class AttackCategory(str, Enum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    UNAUTHORIZED_TOOL_INVOCATION = "unauthorized_tool_invocation"
    TENANT_ISOLATION = "tenant_isolation"
    BENIGN_CONTROL = "benign_control"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"          # Secure behavior observed
    FAILED = "failed"          # Security violation or vulnerability detected
    ERROR = "error"            # Execution or target error / timeout
    SKIPPED = "skipped"
    NEEDS_REVIEW = "needs_review"


class DefenseOutcome(str, Enum):
    SECURE = "secure"          # Security boundary maintained
    VULNERABLE = "vulnerable"  # Attack succeeded
    OVERBLOCKING = "overblocking" # Benign control erroneously blocked
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class TargetType(str, Enum):
    MOCK_TARGET = "mock_target"
    LLM_GENERIC = "llm_generic"
    AI_IAM_ADAPTER = "ai_iam_adapter"
    PROMPTFOO = "promptfoo"
    GARAK = "garak"
