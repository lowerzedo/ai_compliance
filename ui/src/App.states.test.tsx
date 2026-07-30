import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "./api";
import App from "./App";
import {
  configuration,
  historyDetail,
  historyPage,
  idleRun,
  readiness,
} from "./test/fixtures";
import { createMockApi } from "./test/mockApi";
import type { ActiveRunResponse, HistoryDetail, RevealResponse } from "./types";

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("console operational states", () => {
  it("shows the configuration and history empty states", async () => {
    const user = userEvent.setup();
    const api = createMockApi({
      configuration: vi.fn().mockResolvedValue({
        ...configuration,
        suiteLoaded: false,
        policyLoaded: false,
        readyForReview: false,
        review: null,
      }),
      history: vi.fn().mockResolvedValue({
        ...historyPage,
        items: [],
      }),
    });
    render(<App api={api} />);

    expect(
      await screen.findByRole("heading", {
        name: "Two files establish the boundary",
      }),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    expect(
      await screen.findByRole("heading", { name: "No evidence runs found" }),
    ).toBeVisible();
  });

  it("shows a fixed session failure without rendering exception diagnostics", async () => {
    const api = createMockApi({
      establishSession: vi
        .fn()
        .mockRejectedValue(
          new ApiError(
            "invalid_bootstrap",
            "The console launch link is invalid or already used.",
            401,
          ),
        ),
    });
    render(<App api={api} />);

    expect(
      await screen.findByRole("heading", {
        name: "Local session unavailable",
      }),
    ).toBeVisible();
    expect(
      screen.getByText("The console launch link is invalid or already used."),
    ).toBeVisible();
    expect(document.body).not.toHaveTextContent("stack");
  });

  it("renders fixed running progress and disables configuration replacement", async () => {
    const user = userEvent.setup();
    const running: ActiveRunResponse = {
      ...idleRun,
      state: "running",
      runId: "opaque-running",
      scenarioId: "scenario-01",
      stage: "identity_acquisition",
      startedAt: "2099-07-30T10:00:00.000000Z",
    };
    const api = createMockApi({
      activeRun: vi.fn().mockResolvedValue(running),
    });
    render(<App api={api} />);

    expect(
      await screen.findByRole("heading", {
        name: "Acquiring scoped identities",
      }),
    ).toBeVisible();
    expect(
      screen.getByText(/There is no unsafe in-flight cancellation/),
    ).toBeDefined();
    await user.click(screen.getByRole("button", { name: /Configuration/ }));
    const fileInputs =
      document.querySelectorAll<HTMLInputElement>('input[type="file"]');
    expect(fileInputs[0]).toBeDisabled();
    expect(fileInputs[1]).toBeDisabled();
  });

  it("renders a terminal failure category and a safe retry path", async () => {
    const failed: ActiveRunResponse = {
      ...idleRun,
      state: "failed",
      runId: "opaque-failed",
      scenarioId: "scenario-01",
      stage: "failed",
      startedAt: "2099-07-30T10:00:00.000000Z",
      completedAt: "2099-07-30T10:00:05.000000Z",
      failureCategory: "readiness_failed",
    };
    const api = createMockApi({
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness,
      }),
      activeRun: vi.fn().mockResolvedValue(failed),
    });
    render(<App api={api} />);

    expect(
      await screen.findByText("Verification did not complete"),
    ).toBeVisible();
    expect(screen.getByText("readiness failed")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Retry verification" }),
    ).toBeEnabled();
  });

  it("conceals revealed fields after 30 seconds", async () => {
    const user = userEvent.setup();
    const api = createMockApi();
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");

    const timerSpy = vi.spyOn(window, "setTimeout");

    await user.click(screen.getByRole("button", { name: "Reveal values" }));
    expect(await screen.findByText("111122223333")).toBeVisible();
    expect(timerSpy).toHaveBeenCalledWith(expect.any(Function), 30_000);
    const concealCallback = timerSpy.mock.calls.find(
      ([, timeout]) => timeout === 30_000,
    )?.[0];
    act(() => {
      concealCallback?.();
    });
    expect(screen.queryByText("111122223333")).not.toBeInTheDocument();
    expect(screen.getAllByText("••••••••")).toHaveLength(2);
    timerSpy.mockRestore();
  });

  it("conceals revealed fields on navigation and moves focus to main content", async () => {
    const user = userEvent.setup();
    const api = createMockApi();
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");
    await user.click(screen.getByRole("button", { name: "Reveal values" }));
    expect(await screen.findByText("111122223333")).toBeVisible();

    const readinessButton = screen.getByRole("button", {
      name: /Readiness/,
    });
    readinessButton.focus();
    await user.keyboard("{Enter}");
    expect(
      await screen.findByRole("heading", { name: "Readiness preflight" }),
    ).toBeVisible();
    expect(document.activeElement).toBe(
      document.getElementById("main-content"),
    );
    await user.click(screen.getByRole("button", { name: /Configuration/ }));
    expect(screen.queryByText("111122223333")).not.toBeInTheDocument();
  });

  it("ignores a reveal response that resolves after navigation", async () => {
    const user = userEvent.setup();
    const pending = deferred<RevealResponse>();
    const api = createMockApi({
      reveal: vi.fn().mockReturnValue(pending.promise),
    });
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");

    await user.click(screen.getByRole("button", { name: "Reveal values" }));
    await waitFor(() => expect(api.reveal).toHaveBeenCalledOnce());
    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    await act(async () => {
      pending.resolve({
        schemaVersion: "1",
        configurationRevision: 7,
        fields: [
          {
            id: "field-01",
            label: "Target account",
            value: "111122223333",
          },
        ],
        expiresInSeconds: 30,
      });
      await pending.promise;
    });

    expect(document.body).not.toHaveTextContent("111122223333");
    await user.click(screen.getByRole("button", { name: /Configuration/ }));
    expect(screen.getByRole("button", { name: "Reveal values" })).toBeEnabled();
    expect(document.body).not.toHaveTextContent("111122223333");
  });

  it("batches large allowlisted reveals without retaining partial values", async () => {
    const user = userEvent.setup();
    const sensitiveFields = Array.from({ length: 65 }, (_, index) => ({
      id: `field-${String(index + 1).padStart(2, "0")}`,
      kind: "endpoint",
      label: `Authorized field ${index + 1}`,
      masked: "••••••••",
    }));
    const api = createMockApi({
      configuration: vi.fn().mockResolvedValue({
        ...configuration,
        review: {
          ...configuration.review!,
          sensitiveFields,
        },
      }),
      reveal: vi.fn().mockImplementation(async (fieldIds: string[]) => ({
        schemaVersion: "1",
        configurationRevision: 7,
        fields: fieldIds.map((id) => ({
          id,
          label: id,
          value: `revealed-${id}`,
        })),
        expiresInSeconds: 30,
      })),
    });
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");

    await user.click(screen.getByRole("button", { name: "Reveal values" }));

    expect(await screen.findByText("revealed-field-65")).toBeVisible();
    expect(api.reveal).toHaveBeenCalledTimes(2);
    expect(vi.mocked(api.reveal).mock.calls[0]?.[0]).toHaveLength(64);
    expect(vi.mocked(api.reveal).mock.calls[1]?.[0]).toHaveLength(1);
    expect(vi.mocked(api.reveal).mock.calls[0]?.[1]).toBe(7);
    expect(vi.mocked(api.reveal).mock.calls[1]?.[1]).toBe(7);
  });

  it("never publishes partial reveal batches after revision conflict", async () => {
    const user = userEvent.setup();
    const sensitiveFields = Array.from({ length: 65 }, (_, index) => ({
      id: `field-${String(index + 1).padStart(2, "0")}`,
      kind: "endpoint",
      label: `Authorized field ${index + 1}`,
      masked: "••••••••",
    }));
    const api = createMockApi({
      configuration: vi.fn().mockResolvedValue({
        ...configuration,
        review: {
          ...configuration.review!,
          sensitiveFields,
        },
      }),
      reveal: vi
        .fn()
        .mockResolvedValueOnce({
          schemaVersion: "1",
          configurationRevision: 7,
          fields: sensitiveFields.slice(0, 64).map((field) => ({
            id: field.id,
            label: field.label,
            value: `partial-${field.id}`,
          })),
          expiresInSeconds: 30,
        })
        .mockRejectedValueOnce(
          new ApiError(
            "configuration_changed",
            "Configuration changed; review it again.",
            409,
          ),
        ),
    });
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");

    await user.click(screen.getByRole("button", { name: "Reveal values" }));

    expect(
      await screen.findByText("Configuration changed; review it again."),
    ).toBeVisible();
    expect(document.body).not.toHaveTextContent("partial-field");
    expect(screen.getAllByText("••••••••")).toHaveLength(65);
  });

  it("clears a prior plan after an invalid replacement", async () => {
    const user = userEvent.setup();
    const invalidConfiguration = {
      ...configuration,
      configurationRevision: 8,
      readyForReview: false,
      review: null,
      suiteLoaded: false,
    };
    const api = createMockApi({
      configuration: vi
        .fn()
        .mockResolvedValueOnce(configuration)
        .mockResolvedValue(invalidConfiguration),
      uploadSuite: vi
        .fn()
        .mockRejectedValue(
          new ApiError("invalid_configuration", "Suite JSON is invalid.", 422),
        ),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    const input =
      document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(input).not.toBeNull();

    await user.upload(
      input!,
      new File(["not-json"], "invalid.json", {
        type: "application/json",
      }),
    );

    expect(await screen.findByText("Suite JSON is invalid.")).toBeVisible();
    expect(screen.queryByText("Validated plan")).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "Two files establish the boundary",
      }),
    ).toBeVisible();
  });

  it("clears prior readiness before a failed recheck", async () => {
    const user = userEvent.setup();
    const api = createMockApi({
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness,
      }),
      readiness: vi
        .fn()
        .mockRejectedValue(
          new ApiError(
            "readiness_failed",
            "Readiness checks did not complete.",
            422,
          ),
        ),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    await user.click(screen.getByRole("button", { name: /Readiness/ }));
    expect(
      await screen.findByRole("button", { name: "Review verification" }),
    ).toBeEnabled();

    await user.click(
      screen.getByRole("button", { name: "Run preflight again" }),
    );

    expect(
      await screen.findByText("Readiness checks did not complete."),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Review verification" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Preflight has not run" }),
    ).toBeVisible();
  });

  it("rejects recovered readiness for a different configuration revision", async () => {
    const user = userEvent.setup();
    const configurationApi = vi.fn().mockResolvedValue(configuration);
    const api = createMockApi({
      configuration: configurationApi,
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness: {
          ...readiness,
          configurationRevision: configuration.configurationRevision + 1,
        },
      }),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    await waitFor(() => expect(configurationApi).toHaveBeenCalledTimes(2));

    await user.click(screen.getByRole("button", { name: /Readiness/ }));

    expect(
      await screen.findByRole("heading", { name: "Preflight has not run" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Review verification" }),
    ).not.toBeInTheDocument();
  });

  it("refreshes the plan instead of displaying mismatched readiness", async () => {
    const user = userEvent.setup();
    const updatedConfiguration = {
      ...configuration,
      configurationRevision: configuration.configurationRevision + 1,
    };
    const configurationApi = vi
      .fn()
      .mockResolvedValueOnce(configuration)
      .mockResolvedValue(updatedConfiguration);
    const api = createMockApi({
      configuration: configurationApi,
      readiness: vi.fn().mockResolvedValue({
        ...readiness,
        configurationRevision: updatedConfiguration.configurationRevision,
      }),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");

    await user.click(screen.getByRole("button", { name: "Check readiness" }));

    expect(
      await screen.findByText("Configuration changed; review it again."),
    ).toBeVisible();
    expect(configurationApi).toHaveBeenCalledTimes(2);
    expect(
      screen.queryByRole("button", { name: "Review verification" }),
    ).not.toBeInTheDocument();
  });

  it("invalidates pending evidence detail when refresh fails", async () => {
    const user = userEvent.setup();
    const pendingDetail = deferred<HistoryDetail>();
    const api = createMockApi({
      history: vi
        .fn()
        .mockResolvedValueOnce(historyPage)
        .mockRejectedValue(
          new ApiError(
            "history_unavailable",
            "Evidence history could not be verified.",
            422,
          ),
        ),
      historyDetail: vi.fn().mockReturnValue(pendingDetail.promise),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    await screen.findByText("history-record-01");
    await user.click(
      screen.getByRole("button", {
        name: "Open details for run history-record-01",
      }),
    );
    await waitFor(() => expect(api.historyDetail).toHaveBeenCalledOnce());

    await user.click(screen.getByRole("button", { name: "Refresh history" }));
    await act(async () => {
      pendingDetail.resolve(historyDetail);
      await pendingDetail.promise;
    });

    expect(
      await screen.findByText("Evidence history could not be verified."),
    ).toBeVisible();
    expect(screen.queryByText("Evidence detail")).not.toBeInTheDocument();
    expect(screen.queryByText("history-record-01")).not.toBeInTheDocument();
    expect(
      screen.queryByText("/synthetic/evidence/history-record-01"),
    ).not.toBeInTheDocument();
  });

  it("restores focus after paginated evidence history fails", async () => {
    const user = userEvent.setup();
    const api = createMockApi({
      history: vi
        .fn()
        .mockResolvedValueOnce({
          ...historyPage,
          nextCursor: "next-history-page",
        })
        .mockRejectedValue(
          new ApiError(
            "history_unavailable",
            "Evidence history could not be verified.",
            422,
          ),
        ),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    const loadMore = await screen.findByRole("button", {
      name: "Load more runs",
    });

    await user.click(loadMore);

    expect(
      await screen.findByText("Evidence history could not be verified."),
    ).toBeVisible();
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("button", { name: "Refresh history" }),
      ),
    );
  });

  it("keeps a rejected evidence-history state across navigation", async () => {
    const user = userEvent.setup();
    const api = createMockApi({
      history: vi
        .fn()
        .mockRejectedValue(
          new ApiError(
            "history_unsafe",
            "The evidence root contains an unsafe path.",
            409,
          ),
        ),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");
    await waitFor(() => expect(api.history).toHaveBeenCalled());

    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    expect(
      await screen.findByText("Evidence history unavailable"),
    ).toBeVisible();
    expect(
      screen.getByText("The evidence root contains an unsafe path."),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "No evidence runs found" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Configuration/ }));
    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    expect(screen.getByText("Evidence history unavailable")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "No evidence runs found" }),
    ).not.toBeInTheDocument();
  });

  it("renders identity-specific readiness findings", async () => {
    const user = userEvent.setup();
    const identityFindingReadiness = {
      ...readiness,
      ready: false,
      aws: {
        ...readiness.aws,
        ready: false,
        identities: readiness.aws.identities.map((identity) => ({
          ...identity,
          accountMatches: false,
          issues: ["account_mismatch"],
          ready: false,
        })),
      },
    };
    const api = createMockApi({
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness: identityFindingReadiness,
      }),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");

    await user.click(screen.getByRole("button", { name: /Readiness/ }));

    expect(await screen.findByText("account mismatch")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Review verification" }),
    ).toBeDisabled();
  });

  it("expires readiness controls without requiring another render", async () => {
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const timerSpy = vi.spyOn(window, "setTimeout");
    const user = userEvent.setup();
    const api = createMockApi({
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness: {
          ...readiness,
          expiresAt,
        },
      }),
    });
    render(<App api={api} />);

    await screen.findByText("Validated plan");
    await user.click(screen.getByRole("button", { name: /Readiness/ }));
    const review = await screen.findByRole("button", {
      name: "Review verification",
    });
    expect(review).toBeEnabled();
    const expiryCallback = timerSpy.mock.calls.find(
      ([, timeout]) =>
        typeof timeout === "number" && timeout >= 59_000 && timeout <= 60_100,
    )?.[0];
    expect(expiryCallback).toBeDefined();
    act(() => {
      expiryCallback?.();
    });
    expect(review).toBeDisabled();
    expect(screen.getByText("Readiness expired")).toBeVisible();
    expect(screen.getAllByText("Expired").length).toBeGreaterThan(1);
    expect(screen.queryByText("Ready")).not.toBeInTheDocument();
    timerSpy.mockRestore();
  });

  it("keeps system, dark, and light theme selection in memory only", async () => {
    const user = userEvent.setup();
    const storageGet = vi.spyOn(Storage.prototype, "getItem");
    const storageSet = vi.spyOn(Storage.prototype, "setItem");
    const api = createMockApi();
    render(<App api={api} />);
    const theme = await screen.findByRole("combobox", { name: "Color theme" });

    expect(document.documentElement).not.toHaveAttribute("data-theme");
    await user.selectOptions(theme, "dark");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    await user.selectOptions(theme, "light");
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    await user.selectOptions(theme, "system");
    expect(document.documentElement).not.toHaveAttribute("data-theme");
    expect(storageGet).not.toHaveBeenCalled();
    expect(storageSet).not.toHaveBeenCalled();
  });
});
