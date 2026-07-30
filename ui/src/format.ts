import type {
  AssertionStatus,
  HistoryIntegrityState,
  ObservedFacts,
} from "./types";

export function displayIdentifier(value: string): string {
  return value.replaceAll("_", " ").replaceAll("-", " ");
}

export function formatTimestamp(value: string | null): string {
  if (!value) {
    return "Not available";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

export function statusLabel(status: AssertionStatus): string {
  if (status === "INCONCLUSIVE") {
    return "Inconclusive";
  }
  if (status === "SKIPPED") {
    return "Skipped";
  }
  return status.charAt(0) + status.slice(1).toLowerCase();
}

export function integrityLabel(state: HistoryIntegrityState): string {
  return state.charAt(0).toUpperCase() + state.slice(1);
}

export const observedFactLabels: Readonly<Record<keyof ObservedFacts, string>> =
  {
    baseline_canary_observed: "Baseline canary observed",
    boundary_canary_observed: "Boundary canary observed",
    normalized_evidence_state: "Evidence state",
    retrieval_path_exercised: "Retrieval path exercised",
    retrieved_item_count: "Retrieved item count",
    undeclared_synthetic_marker_observed: "Undeclared marker observed",
  };

export function formatFactValue(
  value: string | boolean | number | null | undefined,
): string {
  if (value === null || value === undefined) {
    return "Not established";
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  return String(value).replaceAll("_", " ");
}
