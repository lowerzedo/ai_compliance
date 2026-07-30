import {
  type ChangeEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { ApiError, ConsoleApi, consoleApi, readBootstrapToken } from "./api";
import {
  AppNavigation,
  AuthorizedPlan,
  HistoryMetadata,
  HistoryResultSummary,
  HistoryTable,
  Notice,
  ReadinessSummary,
  ResultMatrix,
  type Screen,
  SectionHeading,
  ShieldMark,
  stageLabel,
  StatusBadge,
  TimeRange,
} from "./components";
import { displayIdentifier, formatTimestamp } from "./format";
import type {
  ActiveRunResponse,
  ConfigurationResponse,
  HistoryDetail,
  HistoryItem,
  HistoryPage,
  ReadinessStateResponse,
  ReadinessResponse,
  RevealResponse,
  SessionResponse,
} from "./types";

type Theme = "system" | "light" | "dark";
type UploadKind = "suite" | "policy";

export interface ConsoleApiContract {
  establishSession(token: string | null): Promise<SessionResponse>;
  configuration(): Promise<ConfigurationResponse>;
  uploadSuite(contents: ArrayBuffer): Promise<ConfigurationResponse>;
  uploadPolicy(contents: ArrayBuffer): Promise<ConfigurationResponse>;
  reveal(
    fields: string[],
    configurationRevision: number,
  ): Promise<RevealResponse>;
  readiness(): Promise<ReadinessResponse>;
  startRun(
    scenarioId: string,
    configurationRevision: number,
  ): Promise<ActiveRunResponse>;
  activeRun(): Promise<ActiveRunResponse>;
  currentReadiness(): Promise<ReadinessStateResponse>;
  history(cursor: string | null, limit?: number): Promise<HistoryPage>;
  historyDetail(runId: string): Promise<HistoryDetail>;
}

interface AppProps {
  api?: ConsoleApiContract;
}

const MAX_SUITE_BYTES = 1024 * 1024;
const MAX_POLICY_BYTES = 64 * 1024;
const REVEAL_BATCH_SIZE = 64;
const CONFIGURATION_CHANGED_MESSAGE = "Configuration changed; review it again.";
const EMPTY_ACTIVE_RUN: ActiveRunResponse = {
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

function safeErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  return "The local console request could not be completed.";
}

function FileLoader({
  kind,
  loaded,
  busy,
  onUpload,
}: {
  kind: UploadKind;
  loaded: boolean;
  busy: boolean;
  onUpload: (kind: UploadKind, event: ChangeEvent<HTMLInputElement>) => void;
}): ReactNode {
  const isSuite = kind === "suite";
  const title = isSuite ? "Verification suite" : "Execution policy";
  const description = isSuite
    ? "Strict JSON describing the reciprocal retrieval scenario."
    : "Operator-owned JSON authorizing the exact AWS boundary.";
  return (
    <section className="file-loader" aria-labelledby={`${kind}-upload-title`}>
      <div className="file-loader-copy">
        <span className="file-type" aria-hidden="true">
          JSON
        </span>
        <div>
          <div className="file-loader-title">
            <h2 id={`${kind}-upload-title`}>{title}</h2>
            {loaded ? <StatusBadge status="ready" label="Loaded" /> : null}
          </div>
          <p>{description}</p>
          <small>
            Maximum size: {isSuite ? "1 MiB" : "64 KiB"}. File contents stay in
            the local console process.
          </small>
        </div>
      </div>
      <label className={`button button-secondary ${busy ? "is-disabled" : ""}`}>
        <span>{loaded ? `Replace ${kind}` : `Load ${kind}`}</span>
        <input
          accept="application/json,.json"
          disabled={busy}
          onChange={(event) => onUpload(kind, event)}
          type="file"
        />
      </label>
    </section>
  );
}

function LoadingShell(): ReactNode {
  return (
    <div className="session-loading" role="status" aria-live="polite">
      <ShieldMark />
      <div>
        <strong>Opening local console</strong>
        <span>Establishing the loopback session.</span>
      </div>
    </div>
  );
}

export default function App({
  api = consoleApi as ConsoleApi,
}: AppProps): ReactNode {
  const [sessionState, setSessionState] = useState<
    "loading" | "ready" | "error"
  >("loading");
  const [screen, setScreen] = useState<Screen>("configuration");
  const [theme, setTheme] = useState<Theme>("system");
  const [configuration, setConfiguration] =
    useState<ConfigurationResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [activeRun, setActiveRun] =
    useState<ActiveRunResponse>(EMPTY_ACTIVE_RUN);
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [historyDetail, setHistoryDetail] = useState<HistoryDetail | null>(
    null,
  );
  const [revealedFields, setRevealedFields] = useState<Record<string, string>>(
    {},
  );
  const [selectedScenarioId, setSelectedScenarioId] = useState("");
  const [executionConfirmed, setExecutionConfirmed] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [historyErrorMessage, setHistoryErrorMessage] = useState<string | null>(
    null,
  );
  const [historyLoading, setHistoryLoading] = useState(false);
  const [readinessExpired, setReadinessExpired] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const historyDetailRef = useRef<HTMLElement>(null);
  const historyRefreshRef = useRef<HTMLButtonElement>(null);
  const historyTriggerRef = useRef<HTMLButtonElement | null>(null);
  const revealTimerRef = useRef<number | null>(null);
  const revealRequestRef = useRef(0);
  const historyRequestRef = useRef(0);
  const historyDetailRequestRef = useRef(0);
  const screenRef = useRef(screen);
  const configurationRevisionRef = useRef<number | null>(null);
  const previousRunStateRef = useRef(activeRun.state);
  screenRef.current = screen;
  configurationRevisionRef.current =
    configuration?.configurationRevision ?? null;

  const hideRevealed = useCallback(() => {
    revealRequestRef.current += 1;
    setRevealedFields({});
    setBusyAction((current) => (current === "reveal" ? null : current));
    if (revealTimerRef.current !== null) {
      window.clearTimeout(revealTimerRef.current);
      revealTimerRef.current = null;
    }
  }, []);

  const loadHistory = useCallback(
    async (cursor: string | null, append = false) => {
      const requestId = ++historyRequestRef.current;
      if (!append) {
        historyDetailRequestRef.current += 1;
        setBusyAction((current) =>
          current?.startsWith("history-") ? null : current,
        );
        setHistoryDetail(null);
        setHistoryItems([]);
        setHistoryCursor(null);
      }
      setHistoryErrorMessage(null);
      setHistoryLoading(true);
      try {
        const page = await api.history(cursor, 50);
        if (requestId !== historyRequestRef.current) {
          return;
        }
        setHistoryItems((current) =>
          append ? [...current, ...page.items] : page.items,
        );
        setHistoryCursor(page.nextCursor);
        setHistoryErrorMessage(null);
      } catch (error) {
        if (requestId === historyRequestRef.current) {
          setHistoryErrorMessage(safeErrorMessage(error));
          window.setTimeout(() => {
            if (
              requestId === historyRequestRef.current &&
              screenRef.current === "history"
            ) {
              historyRefreshRef.current?.focus();
            }
          }, 0);
        }
      } finally {
        if (requestId === historyRequestRef.current) {
          setHistoryLoading(false);
        }
      }
    },
    [api],
  );

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      const bootstrapToken = readBootstrapToken(window.location.hash);
      if (window.location.hash) {
        window.history.replaceState(
          null,
          document.title,
          `${window.location.pathname}${window.location.search}`,
        );
      }
      try {
        await api.establishSession(bootstrapToken);
        let [nextConfiguration, nextRun, readinessState] = await Promise.all([
          api.configuration(),
          api.activeRun(),
          api.currentReadiness(),
        ]);
        if (
          readinessState.readiness !== null &&
          readinessState.readiness.configurationRevision !==
            nextConfiguration.configurationRevision
        ) {
          nextConfiguration = await api.configuration();
          if (
            readinessState.readiness.configurationRevision !==
            nextConfiguration.configurationRevision
          ) {
            readinessState = {
              schemaVersion: "1",
              readiness: null,
            };
          }
        }
        if (!active) {
          return;
        }
        setConfiguration(nextConfiguration);
        setActiveRun(nextRun);
        setReadiness(readinessState.readiness);
        const firstScenario = nextConfiguration.review?.scenarios[0]?.id ?? "";
        setSelectedScenarioId(nextRun.scenarioId ?? firstScenario);
        setSessionState("ready");
        void loadHistory(null);
        if (
          nextRun.state === "running" ||
          nextRun.state === "complete" ||
          nextRun.state === "failed"
        ) {
          setScreen("run");
        }
      } catch (error) {
        if (active) {
          setErrorMessage(safeErrorMessage(error));
          setSessionState("error");
        }
      }
    };
    void initialize();
    return () => {
      active = false;
    };
  }, [api, loadHistory]);

  useEffect(() => {
    if (theme === "system") {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = theme;
    }
  }, [theme]);

  useEffect(() => {
    hideRevealed();
    setErrorMessage(null);
    if (screen !== "history") {
      historyDetailRequestRef.current += 1;
      setBusyAction((current) =>
        current?.startsWith("history-") ? null : current,
      );
      setHistoryDetail(null);
    }
    mainRef.current?.focus();
  }, [hideRevealed, screen]);

  useEffect(() => {
    const concealOnHidden = () => {
      if (document.visibilityState !== "visible") {
        hideRevealed();
      }
    };
    document.addEventListener("visibilitychange", concealOnHidden);
    window.addEventListener("pagehide", hideRevealed);
    return () => {
      document.removeEventListener("visibilitychange", concealOnHidden);
      window.removeEventListener("pagehide", hideRevealed);
    };
  }, [hideRevealed]);

  useEffect(() => {
    if (activeRun.state !== "running") {
      return;
    }
    let polling = false;
    const interval = window.setInterval(() => {
      if (polling) {
        return;
      }
      polling = true;
      void api
        .activeRun()
        .then((run) => setActiveRun(run))
        .catch((error) => setErrorMessage(safeErrorMessage(error)))
        .finally(() => {
          polling = false;
        });
    }, 1000);
    return () => window.clearInterval(interval);
  }, [activeRun.state, api]);

  useEffect(() => {
    const previous = previousRunStateRef.current;
    previousRunStateRef.current = activeRun.state;
    if (
      previous === "running" &&
      (activeRun.state === "complete" || activeRun.state === "failed")
    ) {
      void loadHistory(null);
    }
  }, [activeRun.state, loadHistory]);

  useEffect(() => {
    setReadinessExpired(false);
    if (readiness === null) {
      return;
    }
    const expiresAt = new Date(readiness.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      setReadinessExpired(true);
      return;
    }
    const timer = window.setTimeout(
      () => setReadinessExpired(true),
      Math.min(expiresAt - Date.now() + 1, 2_147_483_647),
    );
    return () => window.clearTimeout(timer);
  }, [readiness]);

  useEffect(() => {
    if (historyDetail !== null) {
      historyDetailRef.current?.focus();
    }
  }, [historyDetail]);

  const review = configuration?.review ?? null;
  const configured = configuration?.readyForReview === true && review !== null;
  const configurationBusy =
    activeRun.state === "running" || busyAction !== null;
  const readinessExpiresAt =
    readiness === null ? Number.NaN : new Date(readiness.expiresAt).getTime();
  const readinessIsExpired =
    readiness !== null &&
    (readinessExpired ||
      !Number.isFinite(readinessExpiresAt) ||
      readinessExpiresAt <= Date.now());
  const readinessCurrent =
    readiness !== null && !readinessIsExpired && readiness.ready;
  const currentScenario = useMemo(
    () =>
      review?.scenarios.find((item) => item.id === selectedScenarioId) ??
      review?.scenarios[0] ??
      null,
    [review, selectedScenarioId],
  );

  const updateConfiguration = (next: ConfigurationResponse) => {
    setConfiguration(next);
    setReadiness(null);
    setExecutionConfirmed(false);
    setActiveRun((current) =>
      current.state === "running" ? current : EMPTY_ACTIVE_RUN,
    );
    hideRevealed();
    const firstScenario = next.review?.scenarios[0]?.id ?? "";
    setSelectedScenarioId(firstScenario);
  };

  const handleUpload = async (
    kind: UploadKind,
    event: ChangeEvent<HTMLInputElement>,
  ) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) {
      return;
    }
    const limit = kind === "suite" ? MAX_SUITE_BYTES : MAX_POLICY_BYTES;
    if (file.size > limit) {
      setErrorMessage(
        `${kind === "suite" ? "Suite" : "Policy"} file exceeds the local size limit.`,
      );
      input.value = "";
      return;
    }
    setBusyAction(`upload-${kind}`);
    setErrorMessage(null);
    hideRevealed();
    setReadiness(null);
    setExecutionConfirmed(false);
    setActiveRun((current) =>
      current.state === "running" ? current : EMPTY_ACTIVE_RUN,
    );
    setConfiguration((current) =>
      current === null
        ? null
        : {
            ...current,
            policyLoaded: kind === "policy" ? false : current.policyLoaded,
            readyForReview: false,
            review: null,
            suiteLoaded: kind === "suite" ? false : current.suiteLoaded,
          },
    );
    try {
      const contents = await file.arrayBuffer();
      const next =
        kind === "suite"
          ? await api.uploadSuite(contents)
          : await api.uploadPolicy(contents);
      updateConfiguration(next);
    } catch (error) {
      const message = safeErrorMessage(error);
      try {
        updateConfiguration(await api.configuration());
      } catch {
        setConfiguration(null);
        setReadiness(null);
        setExecutionConfirmed(false);
        hideRevealed();
      }
      setErrorMessage(message);
    } finally {
      input.value = "";
      setBusyAction(null);
    }
  };

  const handleReveal = async () => {
    const fieldIds = review?.sensitiveFields.map((field) => field.id) ?? [];
    const revision = configuration?.configurationRevision;
    if (!fieldIds.length || revision === undefined) {
      return;
    }
    hideRevealed();
    const requestId = ++revealRequestRef.current;
    setBusyAction("reveal");
    setErrorMessage(null);
    try {
      const fields: RevealResponse["fields"] = [];
      let expiresInSeconds = 30;
      for (
        let offset = 0;
        offset < fieldIds.length;
        offset += REVEAL_BATCH_SIZE
      ) {
        const response = await api.reveal(
          fieldIds.slice(offset, offset + REVEAL_BATCH_SIZE),
          revision,
        );
        if (
          requestId !== revealRequestRef.current ||
          screenRef.current !== "configuration" ||
          configurationRevisionRef.current !== revision ||
          response.configurationRevision !== revision ||
          document.visibilityState !== "visible"
        ) {
          return;
        }
        fields.push(...response.fields);
        expiresInSeconds = Math.min(
          expiresInSeconds,
          response.expiresInSeconds,
        );
      }
      setRevealedFields(
        Object.fromEntries(fields.map((field) => [field.id, field.value])),
      );
      if (revealTimerRef.current !== null) {
        window.clearTimeout(revealTimerRef.current);
      }
      revealTimerRef.current = window.setTimeout(
        hideRevealed,
        Math.min(expiresInSeconds, 30) * 1000,
      );
    } catch (error) {
      if (requestId === revealRequestRef.current) {
        setErrorMessage(safeErrorMessage(error));
      }
    } finally {
      if (requestId === revealRequestRef.current) {
        setBusyAction(null);
      }
    }
  };

  const handleReadiness = async () => {
    const revision = configuration?.configurationRevision;
    if (revision === undefined) {
      return;
    }
    setBusyAction("readiness");
    setErrorMessage(null);
    setReadiness(null);
    setExecutionConfirmed(false);
    try {
      const response = await api.readiness();
      if (
        response.configurationRevision !== revision ||
        configurationRevisionRef.current !== revision
      ) {
        updateConfiguration(await api.configuration());
        setErrorMessage(CONFIGURATION_CHANGED_MESSAGE);
        return;
      }
      setReadiness(response);
      setScreen("readiness");
    } catch (error) {
      setErrorMessage(safeErrorMessage(error));
    } finally {
      setBusyAction(null);
    }
  };

  const handleStartRun = async () => {
    const revision = configuration?.configurationRevision;
    if (!currentScenario || revision === undefined || !executionConfirmed) {
      return;
    }
    setBusyAction("run");
    setErrorMessage(null);
    try {
      const response = await api.startRun(currentScenario.id, revision);
      setActiveRun(response);
      setExecutionConfirmed(false);
      void loadHistory(null);
    } catch (error) {
      setErrorMessage(safeErrorMessage(error));
    } finally {
      setBusyAction(null);
    }
  };

  const handleHistorySelect = async (
    item: HistoryItem,
    trigger: HTMLButtonElement,
  ) => {
    const requestId = ++historyDetailRequestRef.current;
    historyTriggerRef.current = trigger;
    setHistoryDetail(null);
    setBusyAction(`history-${item.runId}`);
    setErrorMessage(null);
    try {
      const detail = await api.historyDetail(item.runId);
      if (
        requestId === historyDetailRequestRef.current &&
        screenRef.current === "history"
      ) {
        setHistoryDetail(detail);
      }
    } catch (error) {
      if (requestId === historyDetailRequestRef.current) {
        setErrorMessage(safeErrorMessage(error));
      }
    } finally {
      if (requestId === historyDetailRequestRef.current) {
        setBusyAction(null);
      }
    }
  };

  const handleHistoryDetailClose = () => {
    historyDetailRequestRef.current += 1;
    setHistoryDetail(null);
    window.setTimeout(() => historyTriggerRef.current?.focus(), 0);
  };

  if (sessionState === "loading") {
    return <LoadingShell />;
  }

  if (sessionState === "error") {
    return (
      <main className="session-error">
        <ShieldMark />
        <h1>Local session unavailable</h1>
        <p>{errorMessage}</p>
        <p className="muted-text">
          Close this tab and launch <code>cai-verify ui</code> again.
        </p>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="topbar">
        <div className="brand">
          <ShieldMark />
          <div>
            <strong>CAI Verify</strong>
            <span>Security Console</span>
          </div>
        </div>
        <div className="local-indicator">
          <span aria-hidden="true" />
          Local session
        </div>
        <label className="theme-control">
          <span>Theme</span>
          <select
            aria-label="Color theme"
            onChange={(event) => setTheme(event.target.value as Theme)}
            value={theme}
          >
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
      </header>

      <div className="workspace">
        <aside className="sidebar">
          <AppNavigation
            configured={configured}
            onNavigate={setScreen}
            readinessAvailable={readiness !== null}
            runAvailable={activeRun.state !== "idle"}
            screen={screen}
          />
          <div className="boundary-note">
            <strong>Local boundary</strong>
            <p>
              Credentials and environment values stay in this process. The
              browser receives normalized facts only.
            </p>
          </div>
        </aside>

        <main
          className="main-content"
          id="main-content"
          ref={mainRef}
          tabIndex={-1}
        >
          {errorMessage ? (
            <Notice title="Request not completed" tone="danger">
              <p>{errorMessage}</p>
            </Notice>
          ) : null}

          {screen === "configuration" ? (
            <div className="screen">
              <SectionHeading
                description="Load the untrusted suite and the separate operator-owned authorization policy. Both files are validated by the local Python engine."
                title="Configure an exact AWS boundary"
              />
              <div className="loader-stack">
                <FileLoader
                  busy={configurationBusy}
                  kind="suite"
                  loaded={configuration?.suiteLoaded ?? false}
                  onUpload={handleUpload}
                />
                <FileLoader
                  busy={configurationBusy}
                  kind="policy"
                  loaded={configuration?.policyLoaded ?? false}
                  onUpload={handleUpload}
                />
              </div>

              {!configured ? (
                <div className="empty-state">
                  <div className="empty-state-mark" aria-hidden="true">
                    2
                  </div>
                  <div>
                    <h2>Two files establish the boundary</h2>
                    <p>
                      The suite declares what to test. The policy independently
                      authorizes the target, identities, actions, and evidence
                      source.
                    </p>
                  </div>
                </div>
              ) : (
                <section
                  aria-labelledby="plan-review-title"
                  className="plan-review"
                >
                  <div className="instrument-header">
                    <div>
                      <h2 id="plan-review-title">Validated plan</h2>
                      <p>{review.suiteDescription}</p>
                    </div>
                    <StatusBadge status="ready" label="Valid" />
                  </div>
                  <dl className="metadata-list plan-metadata">
                    <div>
                      <dt>Suite</dt>
                      <dd>{review.suiteName}</dd>
                    </div>
                    <div>
                      <dt>Target</dt>
                      <dd className="mono-cell">{review.targetId}</dd>
                    </div>
                    <div>
                      <dt>Environment</dt>
                      <dd>{review.targetEnvironment}</dd>
                    </div>
                    <div>
                      <dt>Region</dt>
                      <dd>{review.region ?? "Not declared"}</dd>
                    </div>
                  </dl>

                  <div
                    className="plan-counts"
                    aria-label="Plan component counts"
                  >
                    <span>
                      <strong>{review.identityCount}</strong> identities
                    </span>
                    <span>
                      <strong>{review.actionCount}</strong> actions
                    </span>
                    <span>
                      <strong>{review.probeCount}</strong> probes
                    </span>
                    <span>
                      <strong>{review.assertionCount}</strong> assertions
                    </span>
                  </div>

                  <AuthorizedPlan plan={review.plan} />

                  <div className="subsection-heading">
                    <div>
                      <h3>Reciprocal scenarios</h3>
                      <p>Select the scenario to preflight and run.</p>
                    </div>
                  </div>
                  <div className="scenario-options">
                    {review.scenarios.map((scenario) => (
                      <label className="scenario-option" key={scenario.id}>
                        <input
                          checked={selectedScenarioId === scenario.id}
                          name="scenario"
                          onChange={() => setSelectedScenarioId(scenario.id)}
                          type="radio"
                        />
                        <span>
                          <strong>{scenario.id}</strong>
                          <small>{scenario.description}</small>
                        </span>
                        <span className="direction-count">
                          {scenario.directionCount} directions
                        </span>
                      </label>
                    ))}
                  </div>

                  {review.sensitiveFields.length ? (
                    <div className="sensitive-section">
                      <div className="subsection-heading">
                        <div>
                          <h3>Sensitive configuration</h3>
                          <p>
                            Masked by default. Revealed values are concealed
                            after 30 seconds or when this tab is hidden.
                          </p>
                        </div>
                        {Object.keys(revealedFields).length ? (
                          <button
                            className="button button-quiet button-small"
                            onClick={hideRevealed}
                            type="button"
                          >
                            Conceal values
                          </button>
                        ) : (
                          <button
                            className="button button-quiet button-small"
                            disabled={busyAction !== null}
                            onClick={() => void handleReveal()}
                            type="button"
                          >
                            {busyAction === "reveal"
                              ? "Revealing..."
                              : "Reveal values"}
                          </button>
                        )}
                      </div>
                      <dl className="sensitive-list">
                        {review.sensitiveFields.map((field) => (
                          <div key={field.id}>
                            <dt>
                              {field.label}
                              <span>{displayIdentifier(field.kind)}</span>
                            </dt>
                            <dd
                              className={
                                revealedFields[field.id]
                                  ? "revealed-value"
                                  : "masked-value"
                              }
                            >
                              {revealedFields[field.id] ?? field.masked}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    </div>
                  ) : null}

                  <div className="footer-actions">
                    <p>
                      Readiness uses bounded, read-only AWS checks. It does not
                      execute the application action.
                    </p>
                    <button
                      className="button button-primary"
                      disabled={busyAction !== null}
                      onClick={() => void handleReadiness()}
                      type="button"
                    >
                      {busyAction === "readiness"
                        ? "Checking readiness..."
                        : "Check readiness"}
                    </button>
                  </div>
                </section>
              )}
            </div>
          ) : null}

          {screen === "readiness" ? (
            <div className="screen">
              <SectionHeading
                action={
                  readiness ? (
                    <StatusBadge
                      label={readinessIsExpired ? "Expired" : undefined}
                      status={
                        readinessIsExpired
                          ? "INCONCLUSIVE"
                          : readiness.ready
                            ? "ready"
                            : "not-ready"
                      }
                    />
                  ) : undefined
                }
                description="Preflight confirms that declared identities and evidence sources are usable. It does not establish the runtime control."
                title="Readiness preflight"
              />
              {!readiness ? (
                <div className="empty-state">
                  <div className="empty-state-mark" aria-hidden="true">
                    ✓
                  </div>
                  <div>
                    <h2>Preflight has not run</h2>
                    <p>
                      Run bounded identity and evidence-source checks before
                      executing the reciprocal scenario.
                    </p>
                    <button
                      className="button button-primary"
                      disabled={!configured || busyAction !== null}
                      onClick={() => void handleReadiness()}
                      type="button"
                    >
                      Check readiness
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="preflight-meta">
                    <span>Checked {formatTimestamp(readiness.checkedAt)}</span>
                    <span>Expires {formatTimestamp(readiness.expiresAt)}</span>
                  </div>
                  {readinessIsExpired ? (
                    <Notice title="Readiness expired" tone="warning">
                      <p>
                        These checks are retained only as historical context.
                        Run preflight again before verification.
                      </p>
                    </Notice>
                  ) : null}
                  <ReadinessSummary
                    expired={readinessIsExpired}
                    readiness={readiness}
                  />
                  {readiness.aws.issues.length ||
                  readiness.retrieval.issues.length ? (
                    <Notice title="Preflight findings" tone="warning">
                      <ul className="issue-list">
                        {[
                          ...readiness.aws.issues,
                          ...readiness.retrieval.issues,
                        ].map((issue) => (
                          <li key={issue}>{displayIdentifier(issue)}</li>
                        ))}
                      </ul>
                    </Notice>
                  ) : null}
                  <div className="footer-actions">
                    <button
                      className="button button-secondary"
                      disabled={busyAction !== null}
                      onClick={() => void handleReadiness()}
                      type="button"
                    >
                      Run preflight again
                    </button>
                    <button
                      className="button button-primary"
                      disabled={!readinessCurrent}
                      onClick={() => setScreen("run")}
                      type="button"
                    >
                      Review verification
                    </button>
                  </div>
                </>
              )}
            </div>
          ) : null}

          {screen === "run" ? (
            <div className="screen">
              <SectionHeading
                action={
                  activeRun.state === "running" ? (
                    <StatusBadge status="running" />
                  ) : activeRun.result ? (
                    <StatusBadge status={activeRun.result.aggregateStatus} />
                  ) : undefined
                }
                description="Two non-mutating signed requests are tested in opposite requester directions. Evidence is normalized and finalized locally."
                title="Reciprocal retrieval verification"
              />

              {activeRun.state === "idle" ? (
                <>
                  {readinessIsExpired ? (
                    <Notice title="Readiness expired" tone="warning">
                      <p>
                        Return to readiness and run preflight again before
                        starting verification.
                      </p>
                    </Notice>
                  ) : null}
                  <section className="confirmation-panel">
                    <div className="confirmation-summary">
                      <h2>Confirm the bounded run</h2>
                      <p>
                        This operation performs two declared application
                        requests and two correlated CloudWatch Logs reads in the
                        target region.
                      </p>
                      <dl className="metadata-list">
                        <div>
                          <dt>Scenario</dt>
                          <dd className="mono-cell">
                            {currentScenario?.id ?? "Unavailable"}
                          </dd>
                        </div>
                        <div>
                          <dt>Directions</dt>
                          <dd>{currentScenario?.directionCount ?? 0}</dd>
                        </div>
                        <div>
                          <dt>Mutation policy</dt>
                          <dd>Non-mutating only</dd>
                        </div>
                        <div>
                          <dt>Maximum orchestration time</dt>
                          <dd>5 minutes</dd>
                        </div>
                      </dl>
                    </div>
                    <label className="confirmation-check">
                      <input
                        checked={executionConfirmed}
                        onChange={(event) =>
                          setExecutionConfirmed(event.target.checked)
                        }
                        type="checkbox"
                      />
                      <span>
                        <strong>I reviewed this exact plan</strong>
                        <small>
                          I understand the local process will use the declared
                          scoped AWS identities and evidence source.
                        </small>
                      </span>
                    </label>
                    <div className="footer-actions">
                      <button
                        className="button button-secondary"
                        onClick={() => setScreen("readiness")}
                        type="button"
                      >
                        Back to readiness
                      </button>
                      <button
                        className="button button-primary"
                        disabled={
                          !executionConfirmed ||
                          !readinessCurrent ||
                          busyAction !== null
                        }
                        onClick={() => void handleStartRun()}
                        type="button"
                      >
                        {busyAction === "run"
                          ? "Starting verification..."
                          : "Start verification"}
                      </button>
                    </div>
                  </section>
                </>
              ) : null}

              {activeRun.state === "running" ? (
                <section className="run-progress" aria-live="polite">
                  <div className="progress-symbol" aria-hidden="true">
                    <span />
                  </div>
                  <div>
                    <span className="run-kicker">
                      Bounded execution in progress
                    </span>
                    <h2>{stageLabel(activeRun.stage)}</h2>
                    <p>
                      The current SDK or application operation may take time to
                      reach its fixed timeout. Keep this process running.
                    </p>
                    <TimeRange
                      end={activeRun.completedAt}
                      start={activeRun.startedAt}
                    />
                  </div>
                  <div className="progress-track" aria-hidden="true">
                    <span />
                  </div>
                  <p className="no-cancel-note">
                    There is no unsafe in-flight cancellation. Closing the
                    process can leave an intentionally unfinalized evidence
                    directory.
                  </p>
                </section>
              ) : null}

              {activeRun.state === "failed" ? (
                <>
                  <Notice title="Verification did not complete" tone="danger">
                    <p>
                      The local runner stopped with category{" "}
                      <code>
                        {activeRun.failureCategory
                          ? displayIdentifier(activeRun.failureCategory)
                          : "operational failure"}
                      </code>
                      . No compliance conclusion was produced.
                    </p>
                  </Notice>
                  <div className="footer-actions">
                    <button
                      className="button button-primary"
                      onClick={() => {
                        if (readinessCurrent) {
                          setActiveRun(EMPTY_ACTIVE_RUN);
                        } else {
                          setScreen("readiness");
                        }
                      }}
                      type="button"
                    >
                      {readinessCurrent
                        ? "Retry verification"
                        : "Check readiness"}
                    </button>
                  </div>
                </>
              ) : null}

              {activeRun.state === "complete" && activeRun.result ? (
                <div className="result-stack" aria-live="polite">
                  <section className="aggregate-result">
                    <div>
                      <span className="run-kicker">Aggregate result</span>
                      <div className="aggregate-title">
                        <h2>
                          {activeRun.result.aggregateStatus === "PASS"
                            ? "Both retrieval directions passed"
                            : "Verification requires review"}
                        </h2>
                        <StatusBadge
                          status={activeRun.result.aggregateStatus}
                        />
                      </div>
                      <p>
                        A passing result applies only to these two synthetic
                        requests and their fresh, correlated evidence.
                      </p>
                    </div>
                    <TimeRange
                      end={activeRun.completedAt}
                      start={activeRun.startedAt}
                    />
                  </section>
                  <ResultMatrix results={activeRun.result.report.results} />
                  <section className="evidence-location">
                    <div>
                      <h2>Manifest-verified evidence</h2>
                      <p>
                        The runner finalized the manifest and immediately
                        verified every stored artifact.
                      </p>
                    </div>
                    <code>{activeRun.result.evidencePath}</code>
                  </section>
                  <div className="footer-actions">
                    <button
                      className="button button-secondary"
                      onClick={() => {
                        setScreen("history");
                        void loadHistory(null);
                      }}
                      type="button"
                    >
                      View evidence history
                    </button>
                    <button
                      className="button button-primary"
                      onClick={() => {
                        if (readinessCurrent) {
                          setActiveRun(EMPTY_ACTIVE_RUN);
                        } else {
                          setScreen("readiness");
                        }
                      }}
                      type="button"
                    >
                      {readinessCurrent ? "Run again" : "Check readiness"}
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          {screen === "history" ? (
            <div className="screen">
              <SectionHeading
                action={
                  <button
                    className="button button-quiet button-small"
                    disabled={historyLoading}
                    onClick={() => void loadHistory(null)}
                    ref={historyRefreshRef}
                    type="button"
                  >
                    Refresh history
                  </button>
                }
                description="Only fixed reciprocal bundle records are inspected. Every completed record is checked against its manifest before details are shown."
                title="Local evidence history"
              />
              {historyErrorMessage && !historyLoading ? (
                <Notice title="Evidence history unavailable" tone="danger">
                  <p>{historyErrorMessage}</p>
                  <p>
                    No evidence run is treated as verified or absent until a
                    refresh succeeds.
                  </p>
                </Notice>
              ) : !historyItems.length && !historyLoading ? (
                <div className="empty-state">
                  <div className="empty-state-mark" aria-hidden="true">
                    ∅
                  </div>
                  <div>
                    <h2>No evidence runs found</h2>
                    <p>
                      Completed, invalid, and unfinalized reciprocal runs will
                      appear here after the local evidence root is inspected.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="history-layout">
                  <section aria-labelledby="history-list-title">
                    <h2 className="sr-only" id="history-list-title">
                      Evidence runs
                    </h2>
                    <HistoryTable
                      items={historyItems}
                      onSelect={(item, trigger) =>
                        void handleHistorySelect(item, trigger)
                      }
                      selectedRunId={historyDetail?.runId ?? null}
                    />
                    {historyCursor ? (
                      <div className="load-more-row">
                        <button
                          className="button button-secondary"
                          disabled={historyLoading}
                          onClick={() => void loadHistory(historyCursor, true)}
                          type="button"
                        >
                          {historyLoading
                            ? "Loading runs..."
                            : "Load more runs"}
                        </button>
                      </div>
                    ) : null}
                  </section>

                  {historyDetail ? (
                    <aside
                      aria-labelledby="history-detail-title"
                      aria-live="polite"
                      className="history-detail"
                      ref={historyDetailRef}
                      tabIndex={-1}
                    >
                      <div className="instrument-header">
                        <div>
                          <h2 id="history-detail-title">Evidence detail</h2>
                          <p>Bounded, manifest-verified metadata.</p>
                        </div>
                        <button
                          aria-label="Close evidence detail"
                          className="icon-button"
                          onClick={handleHistoryDetailClose}
                          type="button"
                        >
                          <svg aria-hidden="true" viewBox="0 0 16 16">
                            <path d="m4 4 8 8m0-8-8 8" />
                          </svg>
                        </button>
                      </div>
                      <HistoryMetadata item={historyDetail} />
                      {historyDetail.issues.length ? (
                        <div className="history-issues">
                          <h3>Integrity findings</h3>
                          <ul className="issue-list">
                            {historyDetail.issues.map((issue) => (
                              <li key={issue}>{displayIdentifier(issue)}</li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                      {historyDetail.report ? (
                        <div className="history-report">
                          <h3>Normalized result</h3>
                          <HistoryResultSummary report={historyDetail.report} />
                        </div>
                      ) : (
                        <p className="empty-inline">
                          Normalized results are unavailable for this record.
                        </p>
                      )}
                    </aside>
                  ) : null}
                </div>
              )}
              {historyLoading && !historyItems.length ? (
                <div className="loading-lines" role="status">
                  <span />
                  <span />
                  <span />
                  <span className="sr-only">Loading evidence history</span>
                </div>
              ) : null}
            </div>
          ) : null}
        </main>
      </div>
      <div aria-live="polite" className="sr-only">
        {busyAction ? "Local operation in progress" : ""}
      </div>
    </div>
  );
}
