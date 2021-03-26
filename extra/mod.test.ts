import * as oauth from "./mod.ts";
import * as http from "https://deno.land/std@0.90.0/http/mod.ts";
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";

interface RequestData {
  method: string;
  path: string;
  headers: Headers;
  body: ArrayBuffer;
}

interface MockData {
  server: http.Server;
  requests: RequestData[];
}

function mock(hostname: string, port: number): MockData {
  const server = http.serve({ hostname, port });
  const requests: RequestData[] = [];

  (async () => {
    for await (const request of server) {
      requests.push({
        method: request.method,
        path: request.url,
        headers: request.headers,
        body: await Deno.readAll(request.body),
      });
      request.respond({ status: 200 });
    }
  })();

  return { server, requests };
}

Deno.test("Api - makes a correct GET request (no query)", async () => {
  const { server, requests } = mock("localhost", 25127);

  const api = new oauth.Api({
    consumer: { key: "app-key", secret: "app-secret" },
    token: { key: "user-key", secret: "user-secret" },
    signature: oauth.HMAC_SHA1,
    baseUrl: "http://localhost:25127/v1",
  });

  const response = await api.request("GET", "/profile", {
    params: {
      oauth_nonce: "MusLRVYfe1Z8NaAXnXTdxKdurwRYhRIm",
      oauth_timestamp: 1616697632,
    },
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
