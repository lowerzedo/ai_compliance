export type AssertionStatus =
  | "PASS"
  | "FAIL"
  | "INCONCLUSIVE"
  | "ERROR"
  | "SKIPPED";

export type SensitiveFieldKind =
  | "account"
  | "endpoint"
  | "role"
  | "logGroup"
  | "environmentReference"
  | string;

export interface SensitiveField {
  id: string;
  label: string;
  kind: SensitiveFieldKind;
  masked: string;
}

export interface ScenarioReview {
  id: string;
  description: string;
  directionCount: number;
}

export interface ConfigurationReview {
  suiteName: string;
  suiteDescription: string;
  targetId: string;
  targetEnvironment: string;
  region: string | null;
  scenarios: ScenarioReview[];
  identityCount: number;
  actionCount: number;
  probeCount: number;
  assertionCount: number;
  sensitiveFields: SensitiveField[];
  plan: ConfigurationPlan;
}

export interface ConfigurationPlan {
  authorizationMatched: boolean;
  scenario: string;
  target: {
    environment: string;
    label: string;
    region: string | null;
  };
  evidenceFreshness: {
    maxAge: string;
    clockSkewTolerance: string;
  };
  identities: Array<{ label: string; type: string }>;
  policy: {
    actionCount: number;
    allowCurrentIdentity: boolean;
    evidenceSourceCount: number;
    partition: string;
    region: string;
    roleCount: number;
  };
  directions: Array<{
    id: string;
    action: {
      environmentInputCount: number;
      inputCount: number;
      label: string;
      method: string;
      mutating: boolean;
      pathAuthorized: boolean;
      region: string;
      requester: string;
      service: string;
      timeoutSeconds: number;
      type: string;
    };
    evidence: {
      freshness: string | null;
      label: string;
      logGroupAuthorized: boolean;
      observations: string[];
      reader: string;
      retrievalContractConfigured: boolean;
      type: string;
    };
    assertion: {
      controlReferenceCount: number;
      label: string;
      limitationCount: number;
      type: string;
    };
  }>;
}

export interface ConfigurationResponse {
  schemaVersion: "1";
  configurationRevision: number;
  suiteLoaded: boolean;
  policyLoaded: boolean;
  readyForReview: boolean;
  review: ConfigurationReview | null;
}

export interface RevealResponse {
  schemaVersion: "1";
  configurationRevision: number;
  fields: Array<{ id: string; label: string; value: string }>;
  expiresInSeconds: number;
}

export interface AwsIdentityReadiness {
  label: string;
  type: string;
  ready: boolean;
  accountMatches: boolean | null;
  partitionMatches: boolean | null;
  expiresAt: string | null;
  issues: string[];
}

export interface AwsReadiness {
  ready: boolean;
  region: string | null;
  identities: AwsIdentityReadiness[];
  issues: string[];
}

export interface RetrievalCheck {
  direction: string;
  configurationCompatible: boolean;
  actionIdentityReady: boolean | null;
  evidenceIdentityReady: boolean | null;
  canaryContractReady: boolean;
  sourceAccessible: boolean | null;
  correlationState: string;
  issues: string[];
}

export interface RetrievalReadiness {
  ready: boolean;
  region: string | null;
  checks: RetrievalCheck[];
  issues: string[];
}

export interface ReadinessResponse {
  schemaVersion: "1";
  checkedAt: string;
  expiresAt: string;
  configurationRevision: number;
  scenarioId: string;
  ready: boolean;
  aws: AwsReadiness;
  retrieval: RetrievalReadiness;
}

export type RunState = "idle" | "running" | "complete" | "failed";

export interface ObservedFacts {
  baseline_canary_observed: boolean | null;
  boundary_canary_observed: boolean | null;
  normalized_evidence_state: string;
  retrieval_path_exercised: boolean;
  retrieved_item_count: number | null;
  undeclared_synthetic_marker_observed: boolean | null;
}

export interface DirectionResult {
  direction: string;
  status: AssertionStatus;
  observed: ObservedFacts;
  limitations: string[];
}

export interface ActiveRunResult {
  aggregateStatus: AssertionStatus;
  exitCode: number;
  evidencePath: string;
  report: {
    results: DirectionResult[];
  };
}

export interface ActiveRunResponse {
  schemaVersion: "1";
  state: RunState;
  runId: string | null;
  scenarioId: string | null;
  stage: string | null;
  startedAt: string | null;
  completedAt: string | null;
  failureCategory: string | null;
  result: ActiveRunResult | null;
}

export type HistoryIntegrityState =
  | "verified"
  | "tampered"
  | "malformed"
  | "unsupported"
  | "unfinalized";

export interface HistoryItem {
  runId: string;
  state: HistoryIntegrityState;
  aggregateStatus: AssertionStatus | null;
  scenarioId: string | null;
  targetRegion: string | null;
  issues: string[];
  evidencePath: string | null;
  report: HistoryReport | null;
}

export interface HistoryPage {
  schemaVersion: "1";
  items: HistoryItem[];
  nextCursor: string | null;
}

export interface HistoryReport {
  results: Array<{
    assertionId: string;
    status: AssertionStatus;
  }>;
}

export type HistoryDetail = HistoryItem;

export interface ReadinessStateResponse {
  schemaVersion: "1";
  readiness: ReadinessResponse | null;
}

export interface SessionResponse {
  schemaVersion: "1";
  csrfToken: string;
  expiresInSeconds: number;
}

export interface ApiErrorPayload {
  schemaVersion: "1";
  error: {
    category: string;
    message: string;
  };
}
