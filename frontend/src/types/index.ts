export type AttackCategory =
  | 'direct_prompt_injection'
  | 'indirect_prompt_injection'
  | 'jailbreak'
  | 'system_prompt_leakage'
  | 'unauthorized_tool_invocation'
  | 'tenant_isolation'
  | 'benign_control';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type ExecutionStatus =
  | 'pending'
  | 'running'
  | 'passed'
  | 'failed'
  | 'error'
  | 'skipped'
  | 'needs_review';

export interface HealthStatus {
  status: string;
  version: string;
  environment: string;
  safe_mode: boolean;
  components: Record<string, string>;
}

export interface MetricSnapshot {
  id: string;
  run_id: string;
  total_tests: number;
  attack_attempts: number;
  benign_controls: number;
  attack_success_rate: number | null;
  security_pass_rate: number | null;
  detection_precision: number | null;
  detection_recall: number | null;
  false_positive_rate: number | null;
  benign_acceptance_rate: number | null;
  unauthorized_tool_execution_rate: number | null;
  canary_leakage_rate: number | null;
  tenant_isolation_breach_rate: number | null;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  errors_count: number;
  median_latency_ms: number;
  p95_latency_ms: number;
  small_sample_warning: boolean;
  asr_confidence_interval?: { lower: number; upper: number } | null;
  category_breakdown: Record<string, any>;
  created_at: string;
}

export interface Finding {
  id: string;
  run_id: string;
  title: string;
  description: string;
  category: AttackCategory;
  severity: Severity;
  test_case_id: string;
  attack_input_redacted: string;
  target_output_redacted: string;
  tool_violation_observed: boolean;
  canary_leaked: boolean;
  tenant_isolation_breached: boolean;
  remediation_guidance: string;
  created_at: string;
}

export interface EvaluationRun {
  id: string;
  target_name: string;
  status: ExecutionStatus;
  dataset_version: string;
  total_tests: number;
  completed_tests: number;
  passed_tests: number;
  failed_tests: number;
  errors_count: number;
  findings_count: number;
  created_at: string;
  completed_at?: string | null;
  metrics?: MetricSnapshot | null;
  findings?: Finding[];
  executions?: TestExecution[];
}

export interface TestExecution {
  id: string;
  run_id: string;
  test_case_id: string;
  status: ExecutionStatus;
  defense_outcome: string;
  attack_objective_achieved: boolean;
  duration_ms: number;
  error_message?: string | null;
  target_output_sanitized?: string | null;
  tool_calls_attempted: any[];
  canary_detected: boolean;
  tenant_boundary_violated: boolean;
  evaluation_notes?: string | null;
  created_at: string;
}

export interface ExpectedOutcome {
  must_block_action: boolean;
  must_not_contain_canaries: boolean;
  forbidden_substrings: string[];
  required_substrings: string[];
  expected_tool_name?: string | null;
  expected_tenant_id?: string | null;
}

export interface TestCase {
  test_id: string;
  category: AttackCategory;
  name: string;
  description: string;
  severity: Severity;
  is_benign_control: boolean;
  tags: string[];
  input_prompt: string;
  system_prompt?: string | null;
  retrieved_context?: string | null;
  synthetic_canary?: string | null;
  tenant_id?: string | null;
  user_role?: string | null;
  target_tool_name?: string | null;
  expected_outcome: ExpectedOutcome;
}

export interface TestSuite {
  suite_id: string;
  name: string;
  description: string;
  version: string;
  categories: string[];
}

export interface RunComparisonResult {
  baseline_run_id: string;
  candidate_run_id: string;
  compatibility_warning: boolean;
  delta_asr?: number | null;
  delta_security_pass_rate?: number | null;
  delta_fpr?: number | null;
  new_findings_count: number;
  regressions_count: number;
  improvements_count: number;
  regression_test_ids: string[];
  improvement_test_ids: string[];
  category_diffs: Record<string, any>;
}

export interface TargetConfiguration {
  id: string;
  name: string;
  type: string;
  description: string;
  safe_mode_compatible: boolean;
}
