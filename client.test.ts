import { createBaseParams, createBaseString, OAuthClient } from "./client.ts";
import { PLAINTEXT, HMAC_SHA1 } from "./sign.ts";
import { assert, assertEquals, assertNotEquals } from "./test_deps.ts";

// SIGNATURE BASE STRING -----------------------------------------------------

Deno.test("createBaseString - reproduces RFC example", () => {
  const oauthParams = {
    oauth_consumer_key: "9djdj82h48djs9d2",
    oauth_token: "kkk9d7dh3k39sjv7",
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: 137131201,
    oauth_nonce: "7d8f3e4a",
  };
  const query = new URLSearchParams("b5=%3D%253D&a3=a&c%40=&a2=r%20b");
  const body = new URLSearchParams("c2&a3=2+q");
  const params = createBaseParams(oauthParams, query, body);

  const actual = createBaseString(
    "POST",
    "http://example.com/request",
    params,
  );
  const expected =
    "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" +
    "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" +
    "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" +
    "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" +
    "9d7dh3k39sjv7";

  assertEquals(actual, expected);
});

// Taken from ddo/oauth-1.0a.
Deno.test("createBaseString - reproduces Twitter example", () => {
  const oauthParams = {
    oauth_consumer_key: "xvz1evFS4wEEPTGEFPHBog",
    oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: 1318622958,
    oauth_version: "1.0" as "1.0",
    oauth_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
  };
  const query = new URLSearchParams("include_entities=true");
  const body = new URLSearchParams();
  body.append("status", "Hello Ladies + Gentlemen, a signed OAuth request!");
  const params = createBaseParams(oauthParams, query, body);

  const actual = createBaseString(
    "POST",
    "https://api.twitter.com/1/statuses/update.json",
    params,
  );
  const expected =
    "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&inc" +
    "lude_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%" +
    "26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_" +
    "signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth" +
    "_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth" +
    "_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%" +
    "252C%2520a%2520signed%2520OAuth%2520request%2521";

  assertEquals(actual, expected);
});

// MAIN CLASS ----------------------------------------------------------------

Deno.test("OAuthClient.sign - generates unique nonce on each invocation", () => {
  const client = new OAuthClient({
    consumer: { key: "consumer-key", secret: "consumer-secret" },
    signature: PLAINTEXT,
  });
  const sign1 = client.sign("GET", "https://example.com/");
  const sign2 = client.sign("GET", "https://example.com/");

  assertNotEquals(sign1.oauth_nonce?.length, 0);
  assertNotEquals(sign2.oauth_nonce?.length, 0);
  assertNotEquals(sign1.oauth_nonce, sign2.oauth_nonce);
});

Deno.test("OAuthClient.sign - uses current unix timestamp", () => {
  const client = new OAuthClient({
    consumer: { key: "consumer-key", secret: "consumer-secret" },
    signature: PLAINTEXT,
  });

  const lower = (Date.now() / 1000) | 0;
  const sign = client.sign("GET", "https://example.com/");
  const upper = (Date.now() / 1000) | 0;

  assert(sign.oauth_timestamp);
  assert(sign.oauth_timestamp >= lower);
  assert(sign.oauth_timestamp <= upper);
});

Deno.test("OAuthClient.sign - produces correct PLAINTEXT signature", () => {
  const client = new OAuthClient({
    consumer: { key: "consumer-key", secret: "consumer-secret" },
    signature: PLAINTEXT,
  });
  const sign = client.sign("GET", "https://example.com/", {
    token: { key: "request-key", secret: "request-secret" },
  });

  assertEquals(sign.oauth_signature, "consumer-secret&request-secret");
});

Deno.test("OAuthClient.sign - produces correct HMAC-SHA1 signature (RFC)", () => {
  // https://tools.ietf.org/html/rfc5849#section-3.1
  const client = new OAuthClient({
    consumer: { key: "9djdj82h48djs9d2", secret: "j49sk3j29djd" },
    signature: HMAC_SHA1,
    realm: "Example",
  });
  const sign = client.sign(
    "POST",
    "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b",
    {
      token: { key: "kkk9d7dh3k39sjv7", secret: "dh893hdasih9" },
      params: { oauth_timestamp: 137131201, oauth_nonce: "7d8f3e4a" },
      body: new URLSearchParams("c2&a3=2+q"),
    },
  );

  assertEquals(sign.oauth_signature, "bYT5CMsGcbgUdFHObYMEfcx6bsw=");
});

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

  const body = new URLSearchParams();
  body.append("currentbrowserversion", "1");
  body.append("currentbrowserversion", "5");
  body.append("currentbrowserversion", "dfadfadfa");

  const actual = client.signToHeader(
    "PUT",
    "http://localhost:3737/rest/profiles/" +
      "1ea2a42f-e14d-4057-8bcd-3e0b4514a267/properties?alt=json",
    {
      params: {
        oauth_timestamp: 1445951836,
        oauth_nonce: "tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP",
        oauth_version: "1.0",
      },
      body: body,
    },
  );
  const expected =
    'OAuth realm="https://ddo.me/", oauth_consumer_key="batch-dbc2cd8c-6' +
    'ca8-463b-96e2-6d8683eac6fd", oauth_nonce="tKOQtKan8PHIrIoOlrl17zHkZ' +
    'Q2H5CsP", oauth_signature="ri0lfv4udd2uQmkg5cCPVqLruyk%3D", oauth_s' +
    'ignature_method="HMAC-SHA1", oauth_timestamp="1445951836", oauth_ve' +
    'rsion="1.0"';

  assertEquals(actual, expected);
});
