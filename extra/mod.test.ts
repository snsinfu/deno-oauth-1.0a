import * as oauth from "./mod.ts";
import * as http from "https://deno.land/std@0.91.0/http/mod.ts";
import {
  assertEquals,
  assertThrowsAsync,
} from "https://deno.land/std@0.91.0/testing/asserts.ts";

// MOCK SERVER ---------------------------------------------------------------

interface RequestData {
  method: string;
  path: string;
  headers: Headers;
  body: string;
}

interface MockData {
  server: http.Server;
  requests: RequestData[];
}

function mock(hostname: string, port: number): MockData {
  const server = http.serve({ hostname, port });
  const requests: RequestData[] = [];

  (async () => {
    const utf8 = new TextDecoder("utf8");

    for await (const request of server) {
      requests.push({
        method: request.method,
        path: request.url,
        headers: request.headers,
        body: utf8.decode(await Deno.readAll(request.body)),
      });
      request.respond({ status: 200 });
    }
  })();

  return { server, requests };
}

// MAIN TESTS ----------------------------------------------------------------

Deno.test("Api - sends correct GET request", async () => {
  const { server, requests } = mock("localhost", 25127);

  const api = new oauth.Api({
    consumer: { key: "app-key", secret: "app-secret" },
    signature: oauth.HMAC_SHA1,
    prefix: "http://localhost:25127",
  });

  const examples = [
    // Basic request.
    {
      endpoint: "/endpoint",
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
      },
      expect: {
        path: "/endpoint",
        auth: 'OAuth oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="ORIKP%2BXX%2B1edG%2BVYVxC6d%2FopZ0g%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
      },
    },

    // Extra query parameters.
    {
      endpoint: "/endpoint",
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        query: { page: "1", pagesize: "30" }
      },
      expect: {
        path: "/endpoint?page=1&pagesize=30",
        auth: 'OAuth oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="calTD8SPMeP%2Faxe6LEBfEtWPaSg%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
      },
    },

    // Base query parameters + extra query parameters.
    {
      endpoint: "/endpoint?verifier=abc",
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        query: { page: "1", pagesize: "30" }
      },
      expect: {
        path: "/endpoint?verifier=abc&page=1&pagesize=30",
        auth: 'OAuth oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="gW%2FWc%2B%2Fv%2FX5IC6LnL2xPfurN564%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
      },
    },
  ];

  for (const { endpoint, options, expect } of examples) {
    const response = await api.request("GET", endpoint, options);
    await response.blob();

    const actual = requests.shift()!;

    assertEquals(actual.method, "GET");
    assertEquals(actual.path, expect.path);
    assertEquals(actual.headers.get("Authorization"), expect.auth);
  }

  server.close();
});

Deno.test("Api - sends correct request body", async () => {
  const endpoint = "http://localhost:25128/endpoint";
  const { server, requests } = mock("localhost", 25128);

  const api = new oauth.Api({
    consumer: { key: "app-key", secret: "app-secret" },
    signature: oauth.HMAC_SHA1,
  });

  const examples = [
    // Form data is signed.
    {
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        form: { data: "authorized message" },
      },
      expect: {
        auth: 'OAuth oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="i0ZrXqLbXIU2jZELI9V0E0rWCK0%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
        mime: "application/x-www-form-urlencoded",
        body: "data=authorized+message",
      },
    },

    // JSON is not signed (hashed) by default.
    {
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        json: { data: "authorized message" },
      },
      expect: {
        auth: 'OAuth oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="DDkvvWVgjYDbQzwuIcz%2B5LQA%2B7Q%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
        mime: "application/json",
        body: '{"data":"authorized message"}',
      },
    },

    // JSON is signed via oauth_body_hash if requested.
    {
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        json: { data: "authorized message" },
        hashBody: true,
      },
      expect: {
        auth: 'OAuth oauth_body_hash="wKusgBt7LUqeic8hyHjeORS4Knw%3D", ' +
          'oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="1cKp5xV3Bq%2BK0y%2FoGHz2Z8eoFGw%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
        mime: "application/json",
        body: '{"data":"authorized message"}',
      },
    },

    // Empty body is hashed if requested.
    {
      options: {
        params: { oauth_nonce: "nonce", oauth_timestamp: 100 },
        hashBody: true,
      },
      expect: {
        auth: 'OAuth oauth_body_hash="2jmj7l5rSw0yVb%2FvlWAYkK%2FYBwk%3D", ' +
          'oauth_consumer_key="app-key", ' +
          'oauth_nonce="nonce", ' +
          'oauth_signature="aPCy5%2F4jxIXxXr2Mzu2mJ6XSnko%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="100"',
        mime: null,
        body: "",
      },
    },
  ];

  for (const { options, expect } of examples) {
    const response = await api.request("POST", endpoint, options);
    await response.blob();

    const actual = requests.shift()!;

    assertEquals(actual.method, "POST");
    assertEquals(actual.path, "/endpoint");
    assertEquals(actual.headers.get("Content-Type"), expect.mime);
    assertEquals(actual.headers.get("Authorization"), expect.auth);
    assertEquals(actual.body, expect.body);
  }

  server.close();
});

Deno.test("Api - rejects request having both form and json", async () => {
  const api = new oauth.Api({
    consumer: { key: "app-key", secret: "app-secret" },
    signature: oauth.HMAC_SHA1,
  });

  assertThrowsAsync(() =>
    api.request("POST", "http://example.com", { form: {}, json: {} })
  );
});
