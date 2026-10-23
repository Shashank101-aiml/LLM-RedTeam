/**
 * LLM Sentinel API Client for /api/v1
 */

import {
  EvaluationRun,
  Finding,
  HealthStatus,
  MetricSnapshot,
  RunComparisonResult,
  TargetConfiguration,
  TestCase,
  TestSuite,
} from "../types";

const BASE_URL = "/api/v1";

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${BASE_URL}/health`);
  if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
  return res.json();
}

export async function fetchRuns(
  skip: number = 0,
  limit: number = 50,
  statusFilter?: string
): Promise<EvaluationRun[]> {
  const params = new URLSearchParams({
    skip: skip.toString(),
    limit: limit.toString(),
  });
  if (statusFilter && statusFilter !== "all") {
    params.append("status", statusFilter);
  }
  const res = await fetch(`${BASE_URL}/runs?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch runs: HTTP ${res.status}`);
  return res.json();
}

export async function fetchRun(runId: string): Promise<EvaluationRun> {
  const res = await fetch(`${BASE_URL}/runs/${runId}`);
  if (!res.ok) throw new Error(`Failed to fetch run ${runId}: HTTP ${res.status}`);
  return res.json();
}

export async function createRun(payload: {
  target_name: string;
  notes?: string;
  dataset_version?: string;
  selected_categories?: string[];
}): Promise<EvaluationRun> {
  const res = await fetch(`${BASE_URL}/runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to create run: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchRunFindings(runId: string): Promise<Finding[]> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/findings`);
  if (!res.ok) throw new Error(`Failed to fetch findings for ${runId}: HTTP ${res.status}`);
  return res.json();
}

export async function fetchRunMetrics(runId: string): Promise<MetricSnapshot> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/metrics`);
  if (!res.ok) throw new Error(`Failed to fetch metrics for ${runId}: HTTP ${res.status}`);
  return res.json();
}

export async function compareRuns(
  baselineRunId: string,
  candidateRunId: string
): Promise<RunComparisonResult> {
  const res = await fetch(`${BASE_URL}/compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      baseline_run_id: baselineRunId,
      candidate_run_id: candidateRunId,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to compare runs: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchTestSuites(): Promise<TestSuite[]> {
  const res = await fetch(`${BASE_URL}/test-suites`);
  if (!res.ok) throw new Error(`Failed to fetch test suites: HTTP ${res.status}`);
  return res.json();
}

export async function fetchTestCases(filters?: {
  category?: string;
  severity?: string;
  is_benign_control?: boolean;
}): Promise<TestCase[]> {
  const params = new URLSearchParams();
  if (filters?.category) params.append("category", filters.category);
  if (filters?.severity) params.append("severity", filters.severity);
  if (filters?.is_benign_control !== undefined) {
    params.append("is_benign_control", String(filters.is_benign_control));
  }
  const res = await fetch(`${BASE_URL}/test-cases?${params.toString()}`);
  if (!res.ok) throw new Error(`Failed to fetch test cases: HTTP ${res.status}`);
  return res.json();
}

export async function fetchTargets(): Promise<{
  safe_mode: boolean;
  allowed_target_hosts: string[];
  available_adapters: TargetConfiguration[];
}> {
  const res = await fetch(`${BASE_URL}/targets`);
  if (!res.ok) throw new Error(`Failed to fetch targets: HTTP ${res.status}`);
  return res.json();
}

export function getExportJsonUrl(runId: string): string {
  return `${BASE_URL}/runs/${runId}/export/json`;
}

export function getExportCsvUrl(runId: string): string {
  return `${BASE_URL}/runs/${runId}/export/csv`;
}
