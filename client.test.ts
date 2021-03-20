import { OAuthClient } from "./client.ts";
import { HMAC_SHA1 } from "./sign.ts";
import { assertEquals } from "./test_deps.ts";

// Taken from ddo/oauth-1.0a.
Deno.test("OAuthClient.signToHeader - prepends realm", () => {
  const client = new OAuthClient({
    consumer: {
      key: "batch-dbc2cd8c-6ca8-463b-96e2-6d8683eac6fd",
      secret: "4S4Rvm25CJZWv7HBg5HOhhlRTBSZ7npl",
    },
    realm: "https://ddo.me/",
    signature: HMAC_SHA1,
  });

  const data = new URLSearchParams();
  data.append("currentbrowserversion", "1");
  data.append("currentbrowserversion", "5");
  data.append("currentbrowserversion", "dfadfadfa");
  data.append("alt", "json");

  const result = client.signToHeader(
    "PUT",
    "http://localhost:3737/rest/profiles/1ea2a42f-e14d-4057-8bcd-3e0b4514a267/properties?alt=json",
    {
      params: {
        oauth_timestamp: 1445951836,
        oauth_nonce: "tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP",
      },
      body: data,
    },
  );
  assertEquals(
    result,
    'OAuth realm="https://ddo.me/", oauth_consumer_key="batch-dbc2cd8c-6ca8-463b-96e2-6d8683eac6fd", oauth_nonce="tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP", oauth_signature="ri0lfv4udd2uQmkg5cCPVqLruyk%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1445951836", oauth_version="1.0"',
  );
});
