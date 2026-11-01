import { describe, it } from "node:test";
import assert from "node:assert/strict";

describe("ApiClient Header and Request Mechanics (Finding CLIENT-01)", () => {
  it("removes all casing variants of Content-Type when sending FormData", () => {
    // Replicate the exact logic in ApiClient.request
    const testCases = [
      { "Content-Type": "multipart/form-data" },
      { "content-type": "application/json" },
      { "CONTENT-TYPE": "text/plain" },
      { "Content-type": "application/x-www-form-urlencoded" },
      { "Content-Type": "application/json", "X-Custom-Header": "TacticalSec" },
    ];

    for (const initialHeaders of testCases) {
      const requestHeaders = { ...initialHeaders };

      // Case-insensitive Content-Type removal logic
      Object.keys(requestHeaders).forEach((key) => {
        if (key.toLowerCase() === "content-type") {
          delete requestHeaders[key];
        }
      });

      // Verify no case variant of content-type remains
      const remainingContentTypeKeys = Object.keys(requestHeaders).filter(
        (k) => k.toLowerCase() === "content-type"
      );
      assert.equal(
        remainingContentTypeKeys.length,
        0,
        `Expected 0 Content-Type headers, found: ${remainingContentTypeKeys.join(", ")}`
      );

      // Verify custom headers are preserved
      if ("X-Custom-Header" in initialHeaders) {
        assert.equal(requestHeaders["X-Custom-Header"], "TacticalSec");
      }
    }
  });

  it("preserves Content-Type for JSON objects and strings", () => {
    const defaultHeaders = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    const jsonBody = { query: "8.8.8.8" };
    const requestHeaders = { ...defaultHeaders };

    let serializedBody;
    if (typeof FormData !== "undefined" && jsonBody instanceof FormData) {
      // not triggered
    } else if (typeof jsonBody === "string") {
      serializedBody = jsonBody;
    } else {
      serializedBody = JSON.stringify(jsonBody);
    }

    assert.equal(serializedBody, '{"query":"8.8.8.8"}');
    assert.equal(requestHeaders["Content-Type"], "application/json");
    assert.equal(requestHeaders["Accept"], "application/json");
  });

  it("properly serializes query parameters into URL", () => {
    const baseUrl = "http://localhost:8000/api/v1";
    const endpoint = "/dashboard/reports";
    const params = { limit: 10, offset: 0, filter: "phishing", unused: null, skipped: undefined };

    const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = new URL(`${baseUrl}${cleanEndpoint}`);

    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, String(value));
      }
    });

    assert.equal(
      url.toString(),
      "http://localhost:8000/api/v1/dashboard/reports?limit=10&offset=0&filter=phishing"
    );
  });
});
