import type { ReactNode } from "react";

import {
  formatFactValue,
  formatTimestamp,
  integrityLabel,
  observedFactLabels,
  statusLabel,
} from "./format";
import type {
  AssertionStatus,
  ConfigurationPlan,
  DirectionResult,
  HistoryIntegrityState,
  HistoryItem,
  HistoryReport,
  ReadinessResponse,
} from "./types";

export type Screen = "configuration" | "readiness" | "run" | "history";

const knownStageLabels: Readonly<Record<string, string>> = {
  validation: "Validating configuration",
  authorization: "Authorizing exact plan",
  identity_acquisition: "Acquiring scoped identities",
  first_direction: "Testing first direction",
  direction_one: "Testing first direction",
  second_direction: "Testing second direction",
  direction_two: "Testing second direction",
  evaluation: "Evaluating observations",
  finalization: "Finalizing evidence",
  integrity_verification: "Verifying evidence integrity",
  complete: "Run complete",
  failed: "Run failed",
};

export function stageLabel(stage: string | null): string {
  if (!stage) {
    return "Preparing run";
  }
  return knownStageLabels[stage] ?? "Running bounded verification";
}

export function ShieldMark(): ReactNode {
  return (
    <svg
      aria-hidden="true"
      className="brand-mark"
      viewBox="0 0 32 32"
      fill="none"
    >
      <path
        d="M16 3.5 26 7v7.8c0 6.2-3.8 10.9-10 13.7-6.2-2.8-10-7.5-10-13.7V7l10-3.5Z"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path
        d="m11.5 15.7 3 3 6.2-6.4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
      />
    </svg>
  );
}

export function StatusIcon({
  kind,
}: {
  kind:
    | AssertionStatus
    | HistoryIntegrityState
    | "ready"
    | "not-ready"
    | "running";
}): ReactNode {
  if (kind === "PASS" || kind === "verified" || kind === "ready") {
    return (
      <svg aria-hidden="true" viewBox="0 0 16 16">
        <path d="m3.2 8.2 3 3 6.5-6.5" />
      </svg>
    );
  }
  if (kind === "running") {
    return (
      <svg aria-hidden="true" viewBox="0 0 16 16">
        <path d="M8 3v5l3 2" />
        <circle cx="8" cy="8" r="6" />
      </svg>
    );
  }
  if (kind === "INCONCLUSIVE" || kind === "SKIPPED" || kind === "unfinalized") {
    return (
      <svg aria-hidden="true" viewBox="0 0 16 16">
        <path d="M8 4.2v4.3M8 11.6h.01" />
        <circle cx="8" cy="8" r="6" />
      </svg>
    );
  }
  return (
    <svg aria-hidden="true" viewBox="0 0 16 16">
      <path d="m5 5 6 6m0-6-6 6" />
      <circle cx="8" cy="8" r="6" />
    </svg>
  );
}

export function StatusBadge({
  status,
  label,
}: {
  status:
    | AssertionStatus
    | HistoryIntegrityState
    | "ready"
    | "not-ready"
    | "running";
  label?: string;
}): ReactNode {
  const statusText =
    label ??
    (status === "ready"
      ? "Ready"
      : status === "not-ready"
        ? "Not ready"
        : status === "running"
          ? "Running"
          : status === "verified" ||
              status === "tampered" ||
              status === "malformed" ||
              status === "unsupported" ||
              status === "unfinalized"
            ? integrityLabel(status)
            : statusLabel(status));
  return (
    <span className={`status-badge status-${status.toLowerCase()}`}>
      <StatusIcon kind={status} />
      {statusText}
    </span>
  );
}

export function AppNavigation({
  screen,
  configured,
  readinessAvailable,
  runAvailable,
  onNavigate,
}: {
  screen: Screen;
  configured: boolean;
  readinessAvailable: boolean;
  runAvailable: boolean;
  onNavigate: (screen: Screen) => void;
}): ReactNode {
  const items: Array<{
    id: Screen;
    label: string;
    helper: string;
    enabled: boolean;
  }> = [
    {
      id: "configuration",
      label: "Configuration",
      helper: "Suite and policy",
      enabled: true,
    },
    {
      id: "readiness",
      label: "Readiness",
      helper: "Identity and sources",
      enabled: configured,
    },
    {
      id: "run",
      label: "Verification",
      helper: "Reciprocal retrieval",
      enabled: readinessAvailable || runAvailable,
    },
    {
      id: "history",
      label: "Evidence",
      helper: "Verified local runs",
      enabled: true,
    },
  ];
  return (
    <nav aria-label="Console sections" className="app-nav">
      {items.map((item, index) => (
        <button
          aria-current={screen === item.id ? "page" : undefined}
          className="nav-item"
          disabled={!item.enabled}
          key={item.id}
          onClick={() => onNavigate(item.id)}
          type="button"
        >
          <span className="nav-step" aria-hidden="true">
            {index + 1}
          </span>
          <span>
            <strong>{item.label}</strong>
            <small>{item.helper}</small>
          </span>
        </button>
      ))}
    </nav>
  );
}

export function SectionHeading({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}): ReactNode {
  return (
    <header className="section-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action ? <div className="section-action">{action}</div> : null}
    </header>
  );
}

export function Notice({
  tone,
  title,
  children,
}: {
  tone: "info" | "danger" | "warning" | "success";
  title: string;
  children: ReactNode;
}): ReactNode {
  return (
    <div
      className={`notice notice-${tone}`}
      role={tone === "danger" ? "alert" : "status"}
    >
      <StatusIcon
        kind={
          tone === "success"
            ? "ready"
            : tone === "info"
              ? "running"
              : tone === "warning"
                ? "INCONCLUSIVE"
                : "ERROR"
        }
      />
      <div>
        <strong>{title}</strong>
        <div>{children}</div>
      </div>
    </div>
  );
}

function OutcomeValue({
  value,
  expired,
}: {
  value: boolean | null;
  expired: boolean;
}): ReactNode {
  return (
    <span className="outcome-value">
      {expired
        ? "Expired"
        : value === null
          ? "Not checked"
          : value
            ? "Ready"
            : "Not ready"}
    </span>
  );
}

export function ReadinessSummary({
  readiness,
  expired = false,
}: {
  readiness: ReadinessResponse;
  expired?: boolean;
}): ReactNode {
  return (
    <div className="readiness-stack">
      <section
        aria-labelledby="aws-readiness-title"
        className="instrument-section"
      >
        <div className="instrument-header">
          <div>
            <h2 id="aws-readiness-title">AWS identity boundary</h2>
            <p>Scoped identity acquisition and declared target matching.</p>
          </div>
          <StatusBadge
            label={expired ? "Expired" : undefined}
            status={
              expired
                ? "INCONCLUSIVE"
                : readiness.aws.ready
                  ? "ready"
                  : "not-ready"
            }
          />
        </div>
        {readiness.aws.identities.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Identity</th>
                  <th scope="col">Type</th>
                  <th scope="col">Account</th>
                  <th scope="col">Partition</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {readiness.aws.identities.map((identity) => (
                  <tr key={identity.label}>
                    <th scope="row" className="mono-cell">
                      {identity.label}
                    </th>
                    <td>{identity.type}</td>
                    <td>
                      <OutcomeValue
                        expired={expired}
                        value={identity.accountMatches}
                      />
                    </td>
                    <td>
                      <OutcomeValue
                        expired={expired}
                        value={identity.partitionMatches}
                      />
                    </td>
                    <td>
                      <StatusBadge
                        label={expired ? "Expired" : undefined}
                        status={
                          expired
                            ? "INCONCLUSIVE"
                            : identity.ready
                              ? "ready"
                              : "not-ready"
                        }
                      />
                      {identity.issues.length ? (
                        <ul className="issue-list compact-issue-list">
                          {identity.issues.map((issue) => (
                            <li key={issue}>{issue.replaceAll("_", " ")}</li>
                          ))}
                        </ul>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="empty-inline">No AWS identity checks were returned.</p>
        )}
      </section>

      <section
        aria-labelledby="retrieval-readiness-title"
        className="instrument-section"
      >
        <div className="instrument-header">
          <div>
            <h2 id="retrieval-readiness-title">Retrieval evidence path</h2>
            <p>Canary contract, evidence identity, and log-source access.</p>
          </div>
          <StatusBadge
            label={expired ? "Expired" : undefined}
            status={
              expired
                ? "INCONCLUSIVE"
                : readiness.retrieval.ready
                  ? "ready"
                  : "not-ready"
            }
          />
        </div>
        <div className="direction-list">
          {readiness.retrieval.checks.map((check, index) => {
            const checkReady =
              check.configurationCompatible &&
              check.actionIdentityReady === true &&
              check.evidenceIdentityReady === true &&
              check.canaryContractReady &&
              check.sourceAccessible === true &&
              check.issues.length === 0;
            return (
              <article className="direction-row" key={check.direction}>
                <div className="direction-index" aria-hidden="true">
                  {index + 1}
                </div>
                <div className="direction-body">
                  <div className="direction-title">
                    <h3>Direction {index + 1}</h3>
                    <StatusBadge
                      label={expired ? "Expired" : undefined}
                      status={
                        expired
                          ? "INCONCLUSIVE"
                          : checkReady
                            ? "ready"
                            : "not-ready"
                      }
                    />
                  </div>
                  <dl className="compact-facts">
                    <div>
                      <dt>Action identity</dt>
                      <dd>
                        <OutcomeValue
                          expired={expired}
                          value={check.actionIdentityReady}
                        />
                      </dd>
                    </div>
                    <div>
                      <dt>Evidence identity</dt>
                      <dd>
                        <OutcomeValue
                          expired={expired}
                          value={check.evidenceIdentityReady}
                        />
                      </dd>
                    </div>
                    <div>
                      <dt>Canary contract</dt>
                      <dd>
                        <OutcomeValue
                          expired={expired}
                          value={check.canaryContractReady}
                        />
                      </dd>
                    </div>
                    <div>
                      <dt>Source access</dt>
                      <dd>
                        <OutcomeValue
                          expired={expired}
                          value={check.sourceAccessible}
                        />
                      </dd>
                    </div>
                  </dl>
                  {check.issues.length ? (
                    <ul className="issue-list">
                      {check.issues.map((issue) => (
                        <li key={issue}>{issue.replaceAll("_", " ")}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}

export function AuthorizedPlan({
  plan,
}: {
  plan: ConfigurationPlan;
}): ReactNode {
  return (
    <div className="authorized-plan">
      <div className="subsection-heading">
        <div>
          <h3>Authorized execution plan</h3>
          <p>
            Opaque aliases show the exact chain without exposing account,
            endpoint, role, or log-group values.
          </p>
        </div>
        <StatusBadge
          label={plan.authorizationMatched ? "Authorized" : "Denied"}
          status={plan.authorizationMatched ? "ready" : "not-ready"}
        />
      </div>
      <dl className="compact-facts plan-boundary">
        <div>
          <dt>Target</dt>
          <dd className="mono-cell">{plan.target.label}</dd>
        </div>
        <div>
          <dt>Target region</dt>
          <dd>{plan.target.region ?? "Not declared"}</dd>
        </div>
        <div>
          <dt>Policy boundary</dt>
          <dd>
            {plan.policy.partition} · {plan.policy.region}
          </dd>
        </div>
        <div>
          <dt>Current identity</dt>
          <dd>
            {plan.policy.allowCurrentIdentity ? "Allowed" : "Not allowed"}
          </dd>
        </div>
        <div>
          <dt>Evidence max age</dt>
          <dd>{plan.evidenceFreshness.maxAge}</dd>
        </div>
        <div>
          <dt>Clock-skew tolerance</dt>
          <dd>{plan.evidenceFreshness.clockSkewTolerance}</dd>
        </div>
      </dl>

      <div className="plan-identities">
        <span>Scoped identities</span>
        <div>
          {plan.identities.map((identity) => (
            <code key={identity.label}>
              {identity.label} <small>{identity.type}</small>
            </code>
          ))}
        </div>
      </div>

      <div className="direction-plan-list">
        {plan.directions.map((direction, index) => (
          <section
            aria-labelledby={`plan-${direction.id}`}
            className="direction-plan"
            key={direction.id}
          >
            <div className="direction-plan-heading">
              <span aria-hidden="true">{index + 1}</span>
              <div>
                <h4 id={`plan-${direction.id}`}>Direction {index + 1}</h4>
                <p>
                  {direction.action.requester} requests;{" "}
                  {direction.evidence.reader} reads evidence.
                </p>
              </div>
            </div>
            <div className="table-scroll">
              <table className="plan-table">
                <thead>
                  <tr>
                    <th scope="col">Stage</th>
                    <th scope="col">Type</th>
                    <th scope="col">Boundary facts</th>
                    <th scope="col">Authorization</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <th scope="row">Action</th>
                    <td className="mono-cell">
                      {direction.action.method} {direction.action.service}
                    </td>
                    <td>
                      {direction.action.inputCount} inputs,{" "}
                      {direction.action.timeoutSeconds}s timeout,{" "}
                      {direction.action.mutating ? "mutating" : "non-mutating"}
                    </td>
                    <td>
                      <StatusBadge
                        label={
                          direction.action.pathAuthorized
                            ? "Path authorized"
                            : "Path denied"
                        }
                        status={
                          direction.action.pathAuthorized
                            ? "ready"
                            : "not-ready"
                        }
                      />
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Evidence</th>
                    <td className="mono-cell">{direction.evidence.type}</td>
                    <td>
                      {direction.evidence.observations.join(", ")} · freshness{" "}
                      {direction.evidence.freshness ??
                        plan.evidenceFreshness.maxAge}
                    </td>
                    <td>
                      <StatusBadge
                        label={
                          direction.evidence.logGroupAuthorized
                            ? "Source authorized"
                            : "Source denied"
                        }
                        status={
                          direction.evidence.logGroupAuthorized
                            ? "ready"
                            : "not-ready"
                        }
                      />
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Assertion</th>
                    <td className="mono-cell">{direction.assertion.type}</td>
                    <td>
                      {direction.assertion.controlReferenceCount} control
                      references · {direction.assertion.limitationCount}{" "}
                      limitations
                    </td>
                    <td>
                      <span className="muted-text">
                        Deterministic evaluator
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

export function ResultMatrix({
  results,
}: {
  results: DirectionResult[];
}): ReactNode {
  return (
    <div className="result-matrix">
      {results.map((result, index) => (
        <article
          className="result-direction"
          key={`${result.direction}-${index}`}
        >
          <header>
            <div>
              <span className="direction-label">Direction {index + 1}</span>
              <h3>{result.direction}</h3>
            </div>
            <StatusBadge status={result.status} />
          </header>
          <dl className="fact-list">
            {Object.entries(result.observed).map(([key, value]) => {
              if (!(key in observedFactLabels)) {
                return null;
              }
              return (
                <div key={key}>
                  <dt>
                    {observedFactLabels[key as keyof typeof observedFactLabels]}
                  </dt>
                  <dd>
                    {formatFactValue(
                      value as string | boolean | number | null | undefined,
                    )}
                  </dd>
                </div>
              );
            })}
          </dl>
          <details>
            <summary>View limitations</summary>
            <ul className="limitation-list">
              {result.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </details>
        </article>
      ))}
    </div>
  );
}

export function HistoryTable({
  items,
  selectedRunId,
  onSelect,
}: {
  items: HistoryItem[];
  selectedRunId: string | null;
  onSelect: (item: HistoryItem, trigger: HTMLButtonElement) => void;
}): ReactNode {
  return (
    <div className="table-scroll history-table">
      <table>
        <thead>
          <tr>
            <th scope="col">Run</th>
            <th scope="col">Integrity</th>
            <th scope="col">Result</th>
            <th scope="col">Scenario</th>
            <th scope="col">
              <span className="sr-only">Open details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              className={
                selectedRunId === item.runId ? "is-selected" : undefined
              }
              key={item.runId}
            >
              <th scope="row" className="mono-cell">
                {item.runId}
              </th>
              <td>
                <StatusBadge status={item.state} />
              </td>
              <td>
                {item.aggregateStatus ? (
                  <StatusBadge status={item.aggregateStatus} />
                ) : (
                  <span className="muted-text">Unavailable</span>
                )}
              </td>
              <td className="mono-cell">{item.scenarioId ?? "Unavailable"}</td>
              <td className="action-cell">
                <button
                  aria-label={`Open details for run ${item.runId}`}
                  className="button button-quiet button-small"
                  onClick={(event) => onSelect(item, event.currentTarget)}
                  type="button"
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HistoryMetadata({ item }: { item: HistoryItem }): ReactNode {
  return (
    <dl className="metadata-list">
      <div>
        <dt>Run identifier</dt>
        <dd className="mono-cell">{item.runId}</dd>
      </div>
      <div>
        <dt>Integrity</dt>
        <dd>
          <StatusBadge status={item.state} />
        </dd>
      </div>
      <div>
        <dt>Aggregate result</dt>
        <dd>
          {item.aggregateStatus ? (
            <StatusBadge status={item.aggregateStatus} />
          ) : (
            "Unavailable"
          )}
        </dd>
      </div>
      <div>
        <dt>Scenario</dt>
        <dd className="mono-cell">{item.scenarioId ?? "Unavailable"}</dd>
      </div>
      <div>
        <dt>Target region</dt>
        <dd>{item.targetRegion ?? "Unavailable"}</dd>
      </div>
      {item.evidencePath ? (
        <div>
          <dt>Verified evidence path</dt>
          <dd className="path-value">{item.evidencePath}</dd>
        </div>
      ) : null}
    </dl>
  );
}

export function HistoryResultSummary({
  report,
}: {
  report: HistoryReport;
}): ReactNode {
  return (
    <ul className="history-result-list">
      {report.results.map((result, index) => (
        <li key={result.assertionId}>
          <span>
            Direction {index + 1}
            <small className="mono-cell">{result.assertionId}</small>
          </span>
          <StatusBadge status={result.status} />
        </li>
      ))}
    </ul>
  );
}

export function TimeRange({
  start,
  end,
}: {
  start: string | null;
  end: string | null;
}): ReactNode {
  return (
    <dl className="run-time-range">
      <div>
        <dt>Started</dt>
        <dd>{formatTimestamp(start)}</dd>
      </div>
      <div>
        <dt>Completed</dt>
        <dd>{formatTimestamp(end)}</dd>
      </div>
    </dl>
  );
}
