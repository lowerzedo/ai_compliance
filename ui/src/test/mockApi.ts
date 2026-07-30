import { vi } from "vitest";

import type { ConsoleApiContract } from "../App";
import {
  completedRun,
  configuration,
  historyDetail,
  historyPage,
  idleRun,
  readiness,
} from "./fixtures";

export function createMockApi(
  overrides: Partial<ConsoleApiContract> = {},
): ConsoleApiContract {
  return {
    establishSession: vi.fn().mockResolvedValue({
      schemaVersion: "1",
      csrfToken: "synthetic-csrf-token",
      expiresInSeconds: 28_800,
    }),
    configuration: vi.fn().mockResolvedValue(configuration),
    uploadSuite: vi.fn().mockResolvedValue(configuration),
    uploadPolicy: vi.fn().mockResolvedValue(configuration),
    reveal: vi.fn().mockResolvedValue({
      schemaVersion: "1",
      configurationRevision: 7,
      fields: [
        {
          id: "field-01",
          label: "Target account",
          value: "111122223333",
        },
        {
          id: "field-02",
          label: "CloudWatch log group 1",
          value: "/synthetic/application",
        },
      ],
      expiresInSeconds: 30,
    }),
    readiness: vi.fn().mockResolvedValue(readiness),
    currentReadiness: vi.fn().mockResolvedValue({
      schemaVersion: "1",
      readiness: null,
    }),
    startRun: vi.fn().mockResolvedValue(completedRun),
    activeRun: vi.fn().mockResolvedValue(idleRun),
    history: vi.fn().mockResolvedValue(historyPage),
    historyDetail: vi.fn().mockResolvedValue(historyDetail),
    ...overrides,
  };
}
