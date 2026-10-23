"""
Test case loader and schema validator.
"""

from typing import Any, Dict, List
from app.schemas.test_case import TestCaseBase


class TestCaseLoader:
    """Loads and validates test cases from raw structures."""

    @staticmethod
    def load_from_list(data: List[Dict[str, Any]]) -> List[TestCaseBase]:
        """Validates a list of dictionaries against the TestCase schema."""
        test_cases = []
        for item in data:
            validated = TestCaseBase.model_validate(item)
            test_cases.append(validated)
        return test_cases
