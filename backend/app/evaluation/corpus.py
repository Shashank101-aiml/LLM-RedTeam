"""
Test Corpus and Suite Registry for LLM Sentinel.

Loads and provides access to all versioned attack cases and benign controls.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from app.evaluation.loader import TestCaseLoader
from app.schemas.enums import AttackCategory
from app.schemas.test_case import TestCaseBase
from app.schemas.test_suite import TestSuiteBase


def get_datasets_dir() -> Path:
    # Resolves datasets directory relative to project root
    current = Path(__file__).resolve().parent
    for p in [current, current.parent, current.parent.parent, current.parent.parent.parent]:
        candidate = p / "datasets"
        if candidate.exists() and candidate.is_dir():
            return candidate
    return Path("datasets")


class CorpusRegistry:
    """Manages loading, filtering, and retrieval of test cases and suites."""

    def __init__(self, datasets_dir: Optional[Path] = None):
        self.datasets_dir = datasets_dir or get_datasets_dir()
        self._test_cases: Dict[str, TestCaseBase] = {}
        self._loaded = False

    def load(self) -> None:
        """Loads all JSON attack cases and benign controls."""
        if self._loaded:
            return

        attack_dir = self.datasets_dir / "attack_cases"
        benign_dir = self.datasets_dir / "benign_controls"

        all_cases = []

        if attack_dir.exists():
            for f in attack_dir.glob("*.json"):
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    all_cases.extend(data)

        if benign_dir.exists():
            for f in benign_dir.glob("*.json"):
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    all_cases.extend(data)

        validated = TestCaseLoader.load_from_list(all_cases)
        for tc in validated:
            self._test_cases[tc.test_id] = tc

        self._loaded = True

    def get_all(self) -> List[TestCaseBase]:
        self.load()
        return list(self._test_cases.values())

    def get_by_id(self, test_id: str) -> Optional[TestCaseBase]:
        self.load()
        return self._test_cases.get(test_id)

    def get_by_category(self, category: AttackCategory) -> List[TestCaseBase]:
        self.load()
        return [tc for tc in self._test_cases.values() if tc.category == category]

    def get_available_suites(self) -> List[TestSuiteBase]:
        self.get_all()
        return [
            TestSuiteBase(
                suite_id="full-sentinel-v1",
                name="Complete Sentinel Adversarial & Control Benchmark",
                description="Comprehensive benchmark spanning direct/indirect injection, jailbreaks, canaries, tools, and tenants with benign controls.",
                version="1.0.0",
                categories=[c.value for c in AttackCategory],
            ),
            TestSuiteBase(
                suite_id="owasp-llm-top10",
                name="OWASP LLM Top 10 Core Evaluation",
                description="Prompt injection, sensitive information disclosure, and unauthorized tool invocations.",
                version="1.0.0",
                categories=[
                    AttackCategory.DIRECT_PROMPT_INJECTION.value,
                    AttackCategory.INDIRECT_PROMPT_INJECTION.value,
                    AttackCategory.SYSTEM_PROMPT_LEAKAGE.value,
                    AttackCategory.UNAUTHORIZED_TOOL_INVOCATION.value,
                    AttackCategory.BENIGN_CONTROL.value,
                ],
            ),
            TestSuiteBase(
                suite_id="authorization-and-isolation",
                name="AI-IAM Authorization & Tenant Isolation Benchmark",
                description="Pre-execution tool authorization boundaries and multi-tenant isolation.",
                version="1.0.0",
                categories=[
                    AttackCategory.UNAUTHORIZED_TOOL_INVOCATION.value,
                    AttackCategory.TENANT_ISOLATION.value,
                    AttackCategory.BENIGN_CONTROL.value,
                ],
            ),
        ]


corpus_registry = CorpusRegistry()
