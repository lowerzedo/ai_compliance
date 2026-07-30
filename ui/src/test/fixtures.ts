import type {
  ActiveRunResult,
  ActiveRunResponse,
  ConfigurationResponse,
  HistoryDetail,
  HistoryPage,
  ReadinessResponse,
} from "../types";
import contractResult from "./contract-result.json";

export const configuration: ConfigurationResponse = {
  schemaVersion: "1",
  configurationRevision: 7,
  suiteLoaded: true,
  policyLoaded: true,
  readyForReview: true,
  review: {
    suiteName: "Validated reciprocal suite",
    suiteDescription: "One validated two-direction reciprocal retrieval plan.",
    targetId: "target-01",
    targetEnvironment: "sandbox",
    region: "us-east-1",
    identityCount: 3,
    actionCount: 2,
    probeCount: 2,
    assertionCount: 2,
    scenarios: [
      {
        id: "scenario-01",
        description: "Exact reciprocal retrieval",
        directionCount: 2,
      },
    ],
    sensitiveFields: [
      {
        id: "field-01",
        label: "Target account",
        kind: "account",
        masked: "••••••••",
      },
      {
        id: "field-02",
        label: "CloudWatch log group 1",
        kind: "log_group",
        masked: "••••••••",
      },
    ],
    plan: {
      authorizationMatched: true,
      scenario: "scenario-01",
      target: {
        environment: "sandbox",
        label: "target-01",
        region: "us-east-1",
      },
      evidenceFreshness: {
        maxAge: "PT5M",
        clockSkewTolerance: "PT30S",
      },
      identities: [
        { label: "identity-01", type: "awsAssumedRole" },
        { label: "identity-02", type: "awsAssumedRole" },
        { label: "identity-03", type: "awsAssumedRole" },
      ],
      policy: {
        actionCount: 2,
        allowCurrentIdentity: false,
        evidenceSourceCount: 1,
        partition: "aws",
        region: "us-east-1",
        roleCount: 3,
      },
      directions: [1, 2].map((position) => ({
        id: `direction-0${position}`,
        action: {
          environmentInputCount: 1,
          inputCount: 1,
          label: `action-0${position}`,
          method: "POST",
          mutating: false,
          pathAuthorized: true,
          region: "us-east-1",
          requester: `identity-0${position}`,
          service: "execute-api",
          timeoutSeconds: 10,
          type: "awsSigV4",
        },
        evidence: {
          freshness: "PT5M",
          label: `probe-0${position}`,
          logGroupAuthorized: true,
          observations: ["retrievalCanary"],
          reader: "identity-03",
          retrievalContractConfigured: true,
          type: "cloudWatchLogs",
        },
        assertion: {
          controlReferenceCount: 0,
          label: `assertion-0${position}`,
          limitationCount: 5,
          type: "retrievalBoundary",
        },
      })),
    },
  },
};

export const readiness: ReadinessResponse = {
  schemaVersion: "1",
  configurationRevision: 7,
  scenarioId: "scenario-01",
  checkedAt: "2099-07-30T10:00:00.000000Z",
  expiresAt: "2099-07-30T10:05:00.000000Z",
  ready: true,
  aws: {
    ready: true,
    region: "us-east-1",
    issues: [],
    identities: [
      {
        label: "identity-01",
        type: "awsAssumedRole",
        ready: true,
        accountMatches: true,
        partitionMatches: true,
        expiresAt: "2099-07-30T11:00:00.000000Z",
        issues: [],
      },
    ],
  },
  retrieval: {
    ready: true,
    region: "us-east-1",
    issues: [],
    checks: [
      {
        direction: "direction-01",
        configurationCompatible: true,
        actionIdentityReady: true,
        evidenceIdentityReady: true,
        canaryContractReady: true,
        sourceAccessible: true,
        correlationState: "runtime_required",
        issues: [],
      },
      {
        direction: "direction-02",
        configurationCompatible: true,
        actionIdentityReady: true,
        evidenceIdentityReady: true,
        canaryContractReady: true,
        sourceAccessible: true,
        correlationState: "runtime_required",
        issues: [],
      },
    ],
  },
};

export const idleRun: ActiveRunResponse = {
  schemaVersion: "1",
  state: "idle",
  runId: null,
  scenarioId: null,
  stage: null,
  startedAt: null,
  completedAt: null,
  failureCategory: null,
  result: null,
};

export const completedRun: ActiveRunResponse = {
  schemaVersion: "1",
  state: "complete",
  runId: "opaque-run-01",
  scenarioId: "scenario-01",
  stage: "complete",
  startedAt: "2099-07-30T10:01:00.000000Z",
  completedAt: "2099-07-30T10:01:30.000000Z",
  failureCategory: null,
  result: {
    ...(contractResult as Omit<ActiveRunResult, "evidencePath">),
    evidencePath: "/synthetic/evidence/opaque-run-01",
  },
};

export const historyDetail: HistoryDetail = {
  runId: "history-record-01",
  state: "verified",
  aggregateStatus: "PASS",
  scenarioId: "scenario-01",
  targetRegion: "us-east-1",
  issues: [],
  evidencePath: "/synthetic/evidence/history-record-01",
  report: {
    results: [
      { assertionId: "assertion-public-01", status: "PASS" },
      { assertionId: "assertion-public-02", status: "PASS" },
    ],
  },
};

export const historyPage: HistoryPage = {
  schemaVersion: "1",
  items: [historyDetail],
  nextCursor: null,
};
