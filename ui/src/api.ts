import type {
  ActiveRunResponse,
  ApiErrorPayload,
  ConfigurationResponse,
  HistoryDetail,
  HistoryPage,
  ReadinessResponse,
  ReadinessStateResponse,
  RevealResponse,
  SessionResponse,
} from "./types";

export class ApiError extends Error {
  readonly category: string;
  readonly status: number;

  constructor(category: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.category = category;
    this.status = status;
  }
}

const API_ROOT = "/api/v1";

async function parseResponse<T>(response: Response): Promise<T> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(
      "invalid_response",
      "The local console returned an invalid response.",
      response.status,
    );
  }
  if (!response.ok) {
    const candidate = payload as Partial<ApiErrorPayload>;
    throw new ApiError(
      candidate.error?.category ?? "request_failed",
      candidate.error?.message ?? "The local console request failed.",
      response.status,
    );
  }
  return payload as T;
}

async function fetchJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...init.headers,
    },
  });
  return parseResponse<T>(response);
}

export function readBootstrapToken(locationHash: string): string | null {
  const match = /^#bootstrap=([A-Za-z0-9_-]{32,512})$/.exec(locationHash);
  return match?.[1] ?? null;
}

export class ConsoleApi {
  #csrfToken = "";

  async establishSession(token: string | null): Promise<SessionResponse> {
    const response = token
      ? await fetchJson<SessionResponse>("/session/bootstrap", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        })
      : await fetchJson<SessionResponse>("/session");
    this.#csrfToken = response.csrfToken;
    return response;
  }

  async configuration(): Promise<ConfigurationResponse> {
    return fetchJson<ConfigurationResponse>("/configuration");
  }

  async uploadSuite(contents: ArrayBuffer): Promise<ConfigurationResponse> {
    return this.#mutation<ConfigurationResponse>("/configuration/suite", {
      headers: { "Content-Type": "application/json" },
      body: contents,
    });
  }

  async uploadPolicy(contents: ArrayBuffer): Promise<ConfigurationResponse> {
    return this.#mutation<ConfigurationResponse>("/configuration/policy", {
      headers: { "Content-Type": "application/json" },
      body: contents,
    });
  }

  async reveal(
    fields: string[],
    configurationRevision: number,
  ): Promise<RevealResponse> {
    return this.#mutation<RevealResponse>("/configuration/reveal", {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ configurationRevision, fields }),
    });
  }

  async readiness(): Promise<ReadinessResponse> {
    return this.#mutation<ReadinessResponse>("/readiness");
  }

  async currentReadiness(): Promise<ReadinessStateResponse> {
    return fetchJson<ReadinessStateResponse>("/readiness");
  }

  async startRun(
    scenarioId: string,
    configurationRevision: number,
  ): Promise<ActiveRunResponse> {
    return this.#mutation<ActiveRunResponse>("/runs", {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId, configurationRevision }),
    });
  }

  async activeRun(): Promise<ActiveRunResponse> {
    return fetchJson<ActiveRunResponse>("/runs/active");
  }

  async history(cursor: string | null, limit = 50): Promise<HistoryPage> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (cursor) {
      params.set("cursor", cursor);
    }
    return fetchJson<HistoryPage>(`/history?${params.toString()}`);
  }

  async historyDetail(runId: string): Promise<HistoryDetail> {
    return fetchJson<HistoryDetail>(`/history/${encodeURIComponent(runId)}`);
  }

  async #mutation<T>(
    path: string,
    init: Omit<RequestInit, "method"> = {},
  ): Promise<T> {
    if (!this.#csrfToken) {
      throw new ApiError(
        "session_unavailable",
        "The local console session is unavailable.",
        401,
      );
    }
    return fetchJson<T>(path, {
      ...init,
      method: "POST",
      headers: {
        ...init.headers,
        "X-CSRF-Token": this.#csrfToken,
      },
    });
  }
}

export const consoleApi = new ConsoleApi();
