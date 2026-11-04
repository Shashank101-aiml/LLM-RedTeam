"""
Promptfoo Executable Evaluation & Red-Teaming Integration Package.
"""

from app.integrations.promptfoo.config_generator import (
    PROMPTFOO_CATEGORIES_METADATA,
    PromptfooConfigGenerator,
    get_promptfoo_datasets_dir,
)
from app.integrations.promptfoo.provider import (
    ExternalAuthorizedHTTPAdapter,
    build_test_case_from_vars,
    call_api,
    execute_promptfoo_probe_async,
    resolve_adapter_from_config,
)
from app.integrations.promptfoo.result_parser import (
    PromptfooDetailedItem,
    PromptfooEvaluationParsed,
    PromptfooResultParser,
)
from app.integrations.promptfoo.runner import (
    PromptfooRunner,
    PromptfooRunSummary,
    get_artifacts_dir,
    get_promptfoo_status,
    resolve_promptfoo_command,
)
from app.integrations.promptfoo.validators import (
    CATEGORY_FILE_MAP,
    SUPPORTED_TARGETS,
    validate_path_within_directory,
    validate_promptfoo_config_dict,
    validate_promptfoo_target,
    validate_safe_cli_arg,
    validate_selected_categories,
)

__all__ = [
    "CATEGORY_FILE_MAP",
    "ExternalAuthorizedHTTPAdapter",
    "PROMPTFOO_CATEGORIES_METADATA",
    "PromptfooConfigGenerator",
    "PromptfooDetailedItem",
    "PromptfooEvaluationParsed",
    "PromptfooResultParser",
    "PromptfooRunSummary",
    "PromptfooRunner",
    "SUPPORTED_TARGETS",
    "build_test_case_from_vars",
    "call_api",
    "execute_promptfoo_probe_async",
    "get_artifacts_dir",
    "get_promptfoo_datasets_dir",
    "get_promptfoo_status",
    "resolve_adapter_from_config",
    "resolve_promptfoo_command",
    "validate_path_within_directory",
    "validate_promptfoo_config_dict",
    "validate_promptfoo_target",
    "validate_safe_cli_arg",
    "validate_selected_categories",
]
