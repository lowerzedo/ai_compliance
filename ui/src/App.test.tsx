import axe from "axe-core";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "./App";
import {
  completedRun,
  configuration,
  historyDetail,
  historyPage,
  readiness,
} from "./test/fixtures";
import { createMockApi } from "./test/mockApi";

describe("security console workflow", () => {
  it("recovers the local session and renders the redacted authorized plan", async () => {
    const api = createMockApi();
    render(<App api={api} />);

    expect(
      await screen.findByRole("heading", {
        name: "Configure an exact AWS boundary",
      }),
    ).toBeInTheDocument();
    expect(api.establishSession).toHaveBeenCalledWith(null);
    expect(api.currentReadiness).toHaveBeenCalledOnce();
    expect(screen.getByText("Authorized execution plan")).toBeInTheDocument();
    expect(screen.getAllByText("Path authorized")).toHaveLength(2);
    expect(screen.getAllByText("••••••••")).toHaveLength(2);
    expect(document.body).not.toHaveTextContent("111122223333");
  });

  it("consumes and clears the bootstrap fragment", async () => {
    window.history.replaceState(
      null,
      "",
      `/#bootstrap=synthetic-bootstrap-token-${"x".repeat(32)}`,
    );
    const api = createMockApi();
    render(<App api={api} />);

    await screen.findByRole("heading", {
      name: "Configure an exact AWS boundary",
    });
    expect(api.establishSession).toHaveBeenCalledWith(
      `synthetic-bootstrap-token-${"x".repeat(32)}`,
    );
    expect(window.location.hash).toBe("");
  });

  it("uploads exact file bytes and clears the file input", async () => {
    const user = userEvent.setup();
    const partialConfiguration = {
      ...configuration,
      configurationRevision: 8,
      policyLoaded: false,
      readyForReview: false,
      review: null,
    };
    const api = createMockApi({
      configuration: vi.fn().mockResolvedValue(partialConfiguration),
      uploadSuite: vi.fn().mockResolvedValue(partialConfiguration),
      uploadPolicy: vi.fn().mockResolvedValue(configuration),
    });
    render(<App api={api} />);
    await screen.findByRole("heading", {
      name: "Configure an exact AWS boundary",
    });

    const fileInputs =
      document.querySelectorAll<HTMLInputElement>('input[type="file"]');
    const suiteInput = fileInputs[0];
    const policyInput = fileInputs[1];
    expect(suiteInput).toBeDefined();
    expect(policyInput).toBeDefined();

    const suiteBytes = new Uint8Array([123, 34, 120, 34, 58, 49, 125]);
    const suiteFile = new File([suiteBytes], "suite.json", {
      type: "application/json",
    });
    await user.upload(suiteInput!, suiteFile);
    await waitFor(() => expect(api.uploadSuite).toHaveBeenCalledOnce());
    const sentSuite = vi.mocked(api.uploadSuite).mock.calls[0]?.[0];
    expect(Array.from(new Uint8Array(sentSuite!))).toEqual(
      Array.from(suiteBytes),
    );
    expect(suiteInput?.value).toBe("");

    await user.upload(
      policyInput!,
      new File(['{"schemaVersion":"1alpha1"}'], "policy.json", {
        type: "application/json",
      }),
    );
    await waitFor(() => expect(api.uploadPolicy).toHaveBeenCalledOnce());
    expect(policyInput?.value).toBe("");
  });

  it("reveals allowlisted values and conceals them when the tab is hidden", async () => {
    const user = userEvent.setup();
    const api = createMockApi();
    render(<App api={api} />);
    await screen.findByText("Sensitive configuration");

    await user.click(screen.getByRole("button", { name: "Reveal values" }));
    expect(await screen.findByText("111122223333")).toBeInTheDocument();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    fireEvent(document, new Event("visibilitychange"));
    expect(screen.queryByText("111122223333")).not.toBeInTheDocument();
    expect(screen.getAllByText("••••••••")).toHaveLength(2);
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
  });

  it("runs readiness, requires confirmation, and renders normalized results", async () => {
    const user = userEvent.setup();
    const api = createMockApi();
    render(<App api={api} />);
    await screen.findByText("Validated plan");

    await user.click(screen.getByRole("button", { name: "Check readiness" }));
    expect(
      await screen.findByRole("heading", { name: "Readiness preflight" }),
    ).toBeInTheDocument();
    expect(screen.getByText("AWS identity boundary")).toBeInTheDocument();
    expect(screen.getAllByText("Direction 1").length).toBeGreaterThan(0);

    await user.click(
      screen.getByRole("button", { name: "Review verification" }),
    );
    const start = screen.getByRole("button", { name: "Start verification" });
    expect(start).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", {
        name: /I reviewed this exact plan/i,
      }),
    );
    await user.click(start);

    expect(
      await screen.findByRole("heading", {
        name: "Both retrieval directions passed",
      }),
    ).toBeInTheDocument();
    expect(api.startRun).toHaveBeenCalledWith("scenario-01", 7);
    expect(screen.getAllByText("Baseline canary observed")).toHaveLength(2);
    expect(screen.getByText("/synthetic/evidence/opaque-run-01")).toBeVisible();
  });

  it("recovers an active completed run without executing another readiness check", async () => {
    const api = createMockApi({
      currentReadiness: vi.fn().mockResolvedValue({
        schemaVersion: "1",
        readiness,
      }),
      activeRun: vi.fn().mockResolvedValue(completedRun),
    });
    render(<App api={api} />);

    expect(
      await screen.findByRole("heading", {
        name: "Both retrieval directions passed",
      }),
    ).toBeInTheDocument();
    expect(api.readiness).not.toHaveBeenCalled();
  });

  it("shows verified history with a status-only detail report", async () => {
    const user = userEvent.setup();
    const api = createMockApi({
      history: vi.fn().mockResolvedValue(historyPage),
      historyDetail: vi.fn().mockResolvedValue(historyDetail),
    });
    render(<App api={api} />);
    await screen.findByText("Validated plan");

    await user.click(screen.getByRole("button", { name: /Evidence/ }));
    expect(
      await screen.findByRole("heading", { name: "Local evidence history" }),
    ).toBeInTheDocument();
    const openDetail = screen.getByRole("button", {
      name: "Open details for run history-record-01",
    });
    await user.click(openDetail);
    expect(await screen.findByText("Evidence detail")).toBeInTheDocument();
    const detail = screen.getByRole("complementary", {
      name: "Evidence detail",
    });
    expect(document.activeElement).toBe(detail);
    expect(screen.getByText("assertion-public-01")).toBeInTheDocument();
    expect(screen.getByText("assertion-public-02")).toBeInTheDocument();
    expect(
      screen.getByText("/synthetic/evidence/history-record-01"),
    ).toBeVisible();
    await user.click(
      screen.getByRole("button", { name: "Close evidence detail" }),
    );
    await waitFor(() => expect(document.activeElement).toBe(openDetail));
  });

  it("has no automated accessibility violations in the configured state", async () => {
    const api = createMockApi();
    const { container } = render(<App api={api} />);
    await screen.findByText("Validated plan");

    const results = await axe.run(container, {
      rules: {
        "color-contrast": { enabled: false },
      },
    });
    expect(results.violations).toEqual([]);
  });
});
