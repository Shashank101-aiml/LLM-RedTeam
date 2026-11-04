"""
Promptfoo Configuration Generator and Dataset Loader.

Loads YAML test suites from datasets/promptfoo/ and generates executable Promptfoo
configurations targeting the LLM-RedTeam custom Python provider bridge.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from app.evaluation.corpus import get_datasets_dir
from app.integrations.promptfoo.validators import (
    CATEGORY_FILE_MAP,
    validate_promptfoo_config_dict,
    validate_promptfoo_target,
    validate_selected_categories,
)

ALL_DATASET_FILES: List[str] = [
    "injection.yaml",
    "jailbreak.yaml",
    "data_leakage.yaml",
    "tool_authorization.yaml",
    "benign.yaml",
]

PROMPTFOO_CATEGORIES_METADATA: List[Dict[str, Any]] = [
    {
        "id": "direct_prompt_injection",
        "suite": "injection",
        "name": "Direct Prompt Injection Resistance",
        "description": "Tests whether the target resists direct instruction overrides and delimiter escapes.",
        "dataset_file": "injection.yaml",
    },
    {
        "id": "indirect_prompt_injection",
        "suite": "injection",
        "name": "Indirect Prompt Injection Resistance",
        "description": "Tests whether embedded untrusted instructions in documents/RAG override system rules.",
        "dataset_file": "injection.yaml",
    },
    {
        "id": "jailbreak",
        "suite": "jailbreak",
        "name": "Jailbreak Resistance",
        "description": "Tests role-play, hierarchy manipulation, encoded/obfuscated, multi-part, and safety redefinition attacks.",
        "dataset_file": "jailbreak.yaml",
    },
    {
        "id": "system_prompt_leakage",
        "suite": "data_leakage",
        "name": "System-Prompt and Canary Leakage",
        "description": "Tests disclosure of synthetic system prompts and canary tokens (LLM_REDTEAM_SECRET_7F92A1).",
        "dataset_file": "data_leakage.yaml",
    },
    {
        "id": "unauthorized_tool_invocation",
        "suite": "tool_authorization",
        "name": "Unauthorized Tool Invocation",
        "description": "Tests privileged tool calls, admin escalation, cross-tenant arguments, and post-refusal tool execution.",
        "dataset_file": "tool_authorization.yaml",
    },
    {
        "id": "tenant_isolation",
        "suite": "data_leakage",
        "name": "Sensitive-Data & Cross-Tenant Leakage",
        "description": "Tests exposure of cross-tenant records, synthetic API keys, credentials, and confidential mock documents.",
        "dataset_file": "data_leakage.yaml",
    },
    {
        "id": "benign_control",
        "suite": "benign",
        "name": "Benign Request Acceptance / False Positives",
        "description": "Tests legitimate requests (public docs, harmless code, authorized tools) to measure FPR and BRAR.",
        "dataset_file": "benign.yaml",
    },
]


def get_promptfoo_datasets_dir() -> Path:
    """Returns the datasets/promptfoo directory path."""
    return get_datasets_dir() / "promptfoo"


def get_provider_script_path() -> Path:
    """Returns the absolute path to the Promptfoo Python provider module."""
    return Path(__file__).resolve().parent / "provider.py"


class PromptfooConfigGenerator:
    """Generates and validates Promptfoo YAML configurations from maintainable dataset files."""

    def __init__(self, promptfoo_dir: Optional[Path] = None):
        self.promptfoo_dir = promptfoo_dir or get_promptfoo_datasets_dir()

    def load_tests(self, selected_categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Loads test case entries from datasets/promptfoo/*.yaml filtered by selected_categories.
        """
        validated_cats = validate_selected_categories(selected_categories)

        if not validated_cats:
            files_to_load = list(ALL_DATASET_FILES)
        else:
            files_set = {CATEGORY_FILE_MAP[c] for c in validated_cats}
            files_to_load = [f for f in ALL_DATASET_FILES if f in files_set]

        loaded_tests: List[Dict[str, Any]] = []
        for filename in files_to_load:
            file_path = self.promptfoo_dir / filename
            if not file_path.exists():
                raise FileNotFoundError(f"Promptfoo dataset file not found: {file_path}")
            with open(file_path, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)
            if not isinstance(data, list):
                raise ValueError(f"Expected YAML list of test cases in {filename}, got {type(data).__name__}.")

            for entry in data:
                if not isinstance(entry, dict):
                    continue
                if validated_cats:
                    entry_vars = entry.get("vars", {}) if isinstance(entry.get("vars"), dict) else {}
                    entry_cat = str(entry_vars.get("category", "")).lower()
                    file_stem = filename.replace(".yaml", "").lower()
                    # Match either exact AttackCategory or file suite alias (e.g. 'injection', 'data_leakage')
                    if entry_cat not in validated_cats and file_stem not in validated_cats:
                        # Also allow 'prompt_injection' to match both direct and indirect
                        if not ("prompt_injection" in validated_cats and "prompt_injection" in entry_cat):
                            continue
                loaded_tests.append(entry)

        if not loaded_tests:
            raise ValueError("No Promptfoo test cases matched the selected categories.")

        return loaded_tests

    def generate_config(
        self,
        target: str = "mock-secure",
        selected_categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        safe_mode: Optional[bool] = None,
        authorize_external: bool = False,
        max_concurrency: int = 4,
    ) -> Dict[str, Any]:
        """
        Generates a complete, validated Promptfoo evaluation configuration dictionary.
        """
        target_meta = validate_promptfoo_target(
            target=target,
            endpoint_url=endpoint_url,
            safe_mode=safe_mode,
            authorize_external=authorize_external,
        )
        tests = self.load_tests(selected_categories=selected_categories)

        provider_file = get_provider_script_path().resolve().as_posix()
        provider_id = f"file://{provider_file}:call_api"

        provider_config: Dict[str, Any] = {
            "target": target_meta["id"],
            "mode": target_meta["mode"],
            "safe_mode": target_meta["safe_mode"],
            "authorize_external": authorize_external,
        }
        if target_meta.get("endpoint_url"):
            provider_config["endpoint_url"] = target_meta["endpoint_url"]

        config: Dict[str, Any] = {
            "description": f"LLM-RedTeam Promptfoo Security Evaluation ({target_meta['name']})",
            "prompts": ["{{prompt}}"],
            "providers": [
                {
                    "id": provider_id,
                    "label": target_meta["name"],
                    "config": provider_config,
                }
            ],
            "evaluateOptions": {
                "maxConcurrency": max(1, min(max_concurrency, 10)),
                "showProgressBar": False,
            },
            "tests": tests,
        }

        validate_promptfoo_config_dict(config)
        return config

    def write_config_file(
        self,
        output_path: Path,
        target: str = "mock-secure",
        selected_categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        safe_mode: Optional[bool] = None,
        authorize_external: bool = False,
    ) -> Path:
        """Generates and writes a Promptfoo YAML configuration file to disk."""
        config = self.generate_config(
            target=target,
            selected_categories=selected_categories,
            endpoint_url=endpoint_url,
            safe_mode=safe_mode,
            authorize_external=authorize_external,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write a local provider_bridge.py in the same directory as the config file
        # so Promptfoo resolves `file://provider_bridge.py:call_api` cleanly across
        # different drives (e.g. C: temp dir vs D: workspace on Windows) and OSes.
        backend_dir_posix = get_provider_script_path().resolve().parents[3].as_posix()
        bridge_path = output_path.parent / "provider_bridge.py"
        bridge_code = (
            "import sys\n"
            f"if {backend_dir_posix!r} not in sys.path:\n"
            f"    sys.path.insert(0, {backend_dir_posix!r})\n"
            "from app.integrations.promptfoo.provider import call_api\n"
            "__all__ = ['call_api']\n"
        )
        bridge_path.write_text(bridge_code, encoding="utf-8")
        config["providers"][0]["id"] = "file://provider_bridge.py:call_api"

        with open(output_path, "w", encoding="utf-8") as fp:
            yaml.safe_dump(config, fp, sort_keys=False, allow_unicode=True)
        return output_path
