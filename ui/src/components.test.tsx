import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ResultMatrix, stageLabel, StatusBadge } from "./components";
import type { AssertionStatus, DirectionResult } from "./types";

const observed: DirectionResult["observed"] = {
  baseline_canary_observed: null,
  boundary_canary_observed: null,
  normalized_evidence_state: "partial",
  retrieval_path_exercised: false,
  retrieved_item_count: null,
  undeclared_synthetic_marker_observed: null,
};

describe("normalized result presentation", () => {
  it.each<AssertionStatus>([
    "PASS",
    "FAIL",
    "INCONCLUSIVE",
    "ERROR",
    "SKIPPED",
  ])("renders the %s assertion status with text and an icon", (status) => {
    const { container } = render(<StatusBadge status={status} />);
    expect(
      screen.getByText(
        status === "INCONCLUSIVE" ? "Inconclusive" : new RegExp(status, "i"),
      ),
    ).toBeVisible();
    expect(container.querySelector("svg")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });

  it("renders every status in one direction matrix without exposing unknown fields", () => {
    const statuses: AssertionStatus[] = [
      "PASS",
      "FAIL",
      "INCONCLUSIVE",
      "ERROR",
      "SKIPPED",
    ];
    const results: DirectionResult[] = statuses.map((status, index) => ({
      direction: `direction-0${index + 1}`,
      status,
      observed: {
        ...observed,
        unknown_secret: "not-rendered",
      } as DirectionResult["observed"],
      limitations: ["Synthetic fixed limitation."],
    }));
    render(<ResultMatrix results={results} />);

    for (const status of ["Pass", "Fail", "Inconclusive", "Error", "Skipped"]) {
      expect(screen.getByText(status)).toBeVisible();
    }
    expect(screen.queryByText("not-rendered")).not.toBeInTheDocument();
  });

  it("maps only fixed run progress stages to operator copy", () => {
    expect(stageLabel("identity_acquisition")).toBe(
      "Acquiring scoped identities",
    );
    expect(stageLabel("unexpected-value")).toBe("Running bounded verification");
  });
});
