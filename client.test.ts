import {
  createBaseParams,
  createBaseString,
  OAuthClient,
  toAuthHeader,
  toQueryParams,
} from "./client.ts";
import { HMAC_SHA1, PLAINTEXT } from "./sign.ts";
import { assert, assertEquals, assertNotEquals } from "./test_deps.ts";

// SIGNATURE BASE STRING -----------------------------------------------------

Deno.test("createBaseString - reproduces RFC example", () => {
  const query = new URLSearchParams("b5=%3D%253D&a3=a&c%40=&a2=r%20b");
  const body = new URLSearchParams("c2&a3=2+q");
  const params = createBaseParams(
    {
      oauth_consumer_key: "9djdj82h48djs9d2",
      oauth_token: "kkk9d7dh3k39sjv7",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 137131201,
      oauth_nonce: "7d8f3e4a",
    },
    query,
    body,
  );

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
  const query = new URLSearchParams({
    include_entities: "true",
  });
  const body = new URLSearchParams({
    status: "Hello Ladies + Gentlemen, a signed OAuth request!",
  });
  const params = createBaseParams(
    {
      oauth_consumer_key: "xvz1evFS4wEEPTGEFPHBog",
      oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 1318622958,
      oauth_version: "1.0",
      oauth_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    },
    query,
    body,
  );

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
  // https://www.rfc-editor.org/errata/eid2550
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

  assertEquals(sign.oauth_signature, "r6/TJjbCOr97/+UU0NsvSne7s5g=");
});

// Taken from ddo/oauth-1.0a.
Deno.test("OAuthClient.sign - produces correct parameters (Twitter)", () => {
  const client = new OAuthClient({
    consumer: {
      key: "xvz1evFS4wEEPTGEFPHBog",
      secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    },
    signature: HMAC_SHA1,
  });

  const params = client.sign(
    "POST",
    "https://api.twitter.com/1/statuses/update.json?include_entities=true",
    {
      token: {
        key: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
        secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
      },
      params: {
        oauth_timestamp: 1318622958,
        oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
        oauth_version: "1.0",
      },
      body: new URLSearchParams({
        status: "Hello Ladies + Gentlemen, a signed OAuth request!",
      }),
    },
  );

  assertEquals(
    params,
    {
      oauth_consumer_key: "xvz1evFS4wEEPTGEFPHBog",
      oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 1318622958,
      oauth_version: "1.0",
      oauth_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
      oauth_signature: "tnnArxj06cWHq44gCs1OSKk/jLY=",
    },
  );
});

// Taken from ddo/oauth-1.0a.
Deno.test("OAuthClient.sign - produces correct SHA1 body hash", () => {
  const client = new OAuthClient({
    consumer: {
      key: "1434affd-4d69-4a1a-bace-cc5c6fe493bc",
      secret: "932a216f-fb94-43b6-a2d2-e9c6b345cbea",
    },
    signature: HMAC_SHA1,
  });

  const data = {
    "@context": [
      "http://purl.imsglobal.org/ctx/lti/v2/ToolProxy",
    ],
    "@type": "ToolProxy",
    "lti_version": "LTI-2p1",
    "tool_proxy_guid": "0cf04d67-8a0d-4d41-af61-6e8c6fc3e68c",
    "tool_consumer_profile":
      "http://canvas.docker/api/lti/accounts/1/tool_consumer_profile/339b6700-e4cb-47c5-a54f-3ee0064921a9",
    "tool_profile": {
      "lti_version": "LTI-2p1",
      "product_instance": {
        "guid": "fd75124a-140e-470f-944c-114d2d93db40",
        "product_info": {
          "product_name": {
            "default_value": "TestTool",
            "key": "tool.name",
          },
          "product_version": "0.1.0",
          "product_family": {
            "code": "testtool",
            "vendor": {
              "code": "Example.com",
              "vendor_name": {
                "default_value": "Example",
                "key": "tool.vendor.name",
              },
            },
          },
        },
      },
      "base_url_choice": [
        {
          "default_base_url": "http://example.docker/",
          "selector": {
            "applies_to": [
              "MessageHandler",
            ],
          },
        },
      ],
      "resource_handler": [
        {
          "resource_type": {
            "code": "testtool",
          },
          "resource_name": {
            "default_value": "TestTool",
            "key": "testtool.resource.name",
          },
          "message": [
            {
              "message_type": "basic-lti-launch-request",
              "path": "lti_launch",
              "enabled_capability": [
                "Canvas.placements.courseNavigation",
              ],
            },
          ],
        },
      ],
    },
    "enabled_capability": [
      "OAuth.splitSecret",
    ],
    "security_contract": {
      "tp_half_shared_secret":
        "1c7849d3c9f037a9891575c8508d3aaab6a9e1312b5d0353625f83d68f0d545344f81ff9e1849b6400982a0d3f6bf953c6095265e3b6d700a73f5be94ce5654c",
    },
  };

  const params = client.sign(
    "POST",
    "http://canvas.docker/api/lti/accounts/1/tool_proxy",
    {
      params: {
        oauth_timestamp: 1484599369,
        oauth_nonce: "t62lMDp9DLwKZJJbZTpmSAhRINGBEOcF",
        oauth_version: "1.0",
      },
      body: JSON.stringify(data),
    },
  );

  assertEquals(
    params,
    {
      oauth_consumer_key: "1434affd-4d69-4a1a-bace-cc5c6fe493bc",
      oauth_nonce: "t62lMDp9DLwKZJJbZTpmSAhRINGBEOcF",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 1484599369,
      oauth_version: "1.0",
      oauth_body_hash: "xpJzRG6xylVIRRtiigLPKX7iRmM=",
      oauth_signature: "1Q0U8yhK1bWYguRxlUDs9KHywOE=",
    },
  );
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

  const expected = 'OAuth realm="https://ddo.me/", ' +
    'oauth_consumer_key="batch-dbc2cd8c-6ca8-463b-96e2-6d8683eac6fd", ' +
    'oauth_nonce="tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP", ' +
    'oauth_signature="ri0lfv4udd2uQmkg5cCPVqLruyk%3D", ' +
    'oauth_signature_method="HMAC-SHA1", ' +
    'oauth_timestamp="1445951836", ' +
    'oauth_version="1.0"';

  assertEquals(actual, expected);
});

// POSTPROCESSING ------------------------------------------------------------

// Taken from ddo/oauth-1.0a.
Deno.test("toAuthHeader - produces correct header (Twitter)", () => {
  const actual = toAuthHeader(
    {
      oauth_consumer_key: "xvz1evFS4wEEPTGEFPHBog",
      oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 1318622958,
      oauth_version: "1.0",
      oauth_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
      oauth_signature: "tnnArxj06cWHq44gCs1OSKk/jLY=",
    },
  );

  const expected = 'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", ' +
    'oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", ' +
    'oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", ' +
    'oauth_signature_method="HMAC-SHA1", ' +
    'oauth_timestamp="1318622958", ' +
    'oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", ' +
    'oauth_version="1.0"';

  assertEquals(actual, expected);
});

Deno.test("toAuthHeader - produces correct header with realm (RFC)", () => {
  const actual = toAuthHeader(
    {
      oauth_consumer_key: "9djdj82h48djs9d2",
      oauth_token: "kkk9d7dh3k39sjv7",
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: 137131201,
      oauth_nonce: "7d8f3e4a",
      oauth_signature: "r6/TJjbCOr97/+UU0NsvSne7s5g=",
    },
    "Example",
  );

  // The order of parameters is different from the RFC example because
  // toAuthHeader sorts parameters for consistent output.
  const expected = 'OAuth realm="Example", ' +
    'oauth_consumer_key="9djdj82h48djs9d2", ' +
    'oauth_nonce="7d8f3e4a", ' +
    'oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D", ' +
    'oauth_signature_method="HMAC-SHA1", ' +
    'oauth_timestamp="137131201", ' +
    'oauth_token="kkk9d7dh3k39sjv7"';

  assertEquals(actual, expected);
});

Deno.test("toAuthHeader - escapes special characters in realm", () => {
  const actual = toAuthHeader(
    {
      oauth_consumer_key: "key",
      oauth_signature_method: "PLAINTEXT",
      oauth_signature: "secret&",
    },
    'abc:"123 \\ 456"',
  );

  // realm is escaped as a quoted-string.
  const expected = 'OAuth realm="abc:\\"123 \\\\ 456\\"", ' +
    'oauth_consumer_key="key", ' +
    'oauth_signature="secret%26", ' +
    'oauth_signature_method="PLAINTEXT"';

  assertEquals(actual, expected);
});

Deno.test("toQueryParams - produces correct query params (RFC)", () => {
  const actual = toQueryParams({
    oauth_consumer_key: "0685bd9184jfhq22",
    oauth_token: "ad180jjd733klru7",
    oauth_signature_method: "HMAC-SHA1",
    oauth_signature: "wOJIO9A2W5mFwDgiDvZbTSMK/PY=",
    oauth_timestamp: 137131200,
    oauth_nonce: "4572616e48616d6d65724c61686176",
    oauth_version: "1.0",
  });

  const expected = new URLSearchParams(
    "oauth_consumer_key=0685bd9184jfhq22&oauth_token=ad180jjd733klr" +
    "u7&oauth_signature_method=HMAC-SHA1&oauth_signature=wOJIO9A2W5" +
    "mFwDgiDvZbTSMK%2FPY%3D&oauth_timestamp=137131200&oauth_nonce=4",
  );

  assertEquals(actual, expected);
});
