import { afterEach, describe, expect, it, vi } from "vitest";

import { ConsoleApi, readBootstrapToken } from "./api";

describe("ConsoleApi", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("accepts only one exact bounded bootstrap fragment", () => {
    const token = `capability_${"x".repeat(32)}`;
    expect(readBootstrapToken(`#bootstrap=${token}`)).toBe(token);
    expect(readBootstrapToken(`#bootstrap=${token}&extra=value`)).toBeNull();
    expect(readBootstrapToken("#bootstrap=too-short")).toBeNull();
    expect(readBootstrapToken(`#token=${token}`)).toBeNull();
    expect(readBootstrapToken(`#session=${token}`)).toBeNull();
    expect(readBootstrapToken(`#${token}`)).toBeNull();
    expect(readBootstrapToken("#unrelated=value")).toBeNull();
    expect(readBootstrapToken(`#bootstrap=${"x".repeat(513)}`)).toBeNull();
    expect(readBootstrapToken("")).toBeNull();
  });

  it("sends the in-memory CSRF token on mutations and preserves upload bytes", async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = [];
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push([input, init]);
        if (String(input).endsWith("/session/bootstrap")) {
          return new Response(
            JSON.stringify({
              schemaVersion: "1",
              csrfToken: "csrf-value",
              expiresInSeconds: 28_800,
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          );
        }
        return new Response(
          JSON.stringify({
            schemaVersion: "1",
            configurationRevision: 1,
            suiteLoaded: true,
            policyLoaded: false,
            readyForReview: false,
            review: null,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new ConsoleApi();
    await api.establishSession("bootstrap-value");
    const bytes = new Uint8Array([0xff, 0xfe, 0x7b]).buffer;
    await api.uploadSuite(bytes);

    const upload = calls[1]?.[1];
    expect(new Headers(upload?.headers).get("X-CSRF-Token")).toBe("csrf-value");
    expect(new Headers(upload?.headers).get("Content-Type")).toBe(
      "application/json",
    );
    expect(Array.from(new Uint8Array(upload?.body as ArrayBuffer))).toEqual([
      0xff, 0xfe, 0x7b,
    ]);
    expect(upload?.credentials).toBe("same-origin");
  });

  it("uses same-origin credentials and the exact integer run revision", async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) => {
        const isSession = String(input).endsWith("/session");
        return new Response(
          JSON.stringify(
            isSession
              ? {
                  schemaVersion: "1",
                  csrfToken: "csrf-value",
                  expiresInSeconds: 28_800,
                }
              : {
                  schemaVersion: "1",
                  state: "running",
                  runId: "opaque",
                  scenarioId: "scenario-01",
                  stage: "validation",
                  startedAt: null,
                  completedAt: null,
                  failureCategory: null,
                  result: null,
                },
          ),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new ConsoleApi();
    await api.establishSession(null);
    await api.startRun("scenario-01", 9);

    const request = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(request.credentials).toBe("same-origin");
    expect(JSON.parse(request.body as string)).toEqual({
      scenarioId: "scenario-01",
      configurationRevision: 9,
    });
  });

  it("binds sensitive reveal requests to the exact configuration revision", async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) => {
        const isSession = String(input).endsWith("/session");
        return new Response(
          JSON.stringify(
            isSession
              ? {
                  schemaVersion: "1",
                  csrfToken: "csrf-value",
                  expiresInSeconds: 28_800,
                }
              : {
                  schemaVersion: "1",
                  configurationRevision: 17,
                  fields: [],
                  expiresInSeconds: 30,
                },
          ),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    const api = new ConsoleApi();
    await api.establishSession(null);
    await api.reveal(["field-01"], 17);

    const request = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      configurationRevision: 17,
      fields: ["field-01"],
    });
  });
});
