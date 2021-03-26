import * as oauth from "./mod.ts";
import * as http from "https://deno.land/std@0.91.0/http/mod.ts";
import { assertEquals } from "https://deno.land/std@0.91.0/testing/asserts.ts";

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

Deno.test("Api - makes a correct GET request (no query)", async () => {
  const { server, requests } = mock("localhost", 25127);

  const api = new oauth.Api({
    consumer: { key: "app-key", secret: "app-secret" },
    signature: oauth.HMAC_SHA1,
    prefix: "http://localhost:25127/v1",
  });

  const response = await api.request("GET", "/profile", {
    params: {
      oauth_nonce: "MusLRVYfe1Z8NaAXnXTdxKdurwRYhRIm",
      oauth_timestamp: 1616697632,
    },
    token: { key: "user-key", secret: "user-secret" },
  });
  await response.blob();

  assertEquals(requests.length, 1);

  const expectedAuth = 'OAuth oauth_consumer_key="app-key", ' +
    'oauth_nonce="MusLRVYfe1Z8NaAXnXTdxKdurwRYhRIm", ' +
    'oauth_signature="yv2X7DLlhZ7EiixdaSaGRGzktCw%3D", ' +
    'oauth_signature_method="HMAC-SHA1", ' +
    'oauth_timestamp="1616697632", ' +
    'oauth_token="user-key"';

  const actual = requests[0];
  assertEquals(actual.method, "GET");
  assertEquals(actual.path, "/v1/profile");
  assertEquals(actual.headers.get("Authorization"), expectedAuth);

  server.close();
});

Deno.test("Api - sends correct request body", async () => {
  const endpoint = `http://localhost:25128/endpoint`;
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
    }
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
