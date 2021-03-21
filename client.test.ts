import { createBaseParams, createBaseString, OAuthClient } from "./client.ts";
import { HMAC_SHA1 } from "./sign.ts";
import { assertEquals } from "./test_deps.ts";

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
  const params = [
    {
      key: "oauth_consumer_key",
      value: "xvz1evFS4wEEPTGEFPHBog",
    },
    {
      key: "oauth_nonce",
      value: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
    },
    {
      key: "oauth_signature_method",
      value: "HMAC-SHA1",
    },
    {
      key: "oauth_timestamp",
      value: "1318622958",
    },
    {
      key: "oauth_version",
      value: "1.0",
    },
    {
      key: "oauth_token",
      value: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    },
    {
      key: "include_entities",
      value: "true",
    },
    {
      key: "status",
      value: "Hello Ladies + Gentlemen, a signed OAuth request!",
    },
  ];
  const method = "POST";
  const baseUrl = "https://api.twitter.com/1/statuses/update.json";
  const expected =
    "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521";

  assertEquals(createBaseString(method, baseUrl, params), expected);
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

  const data = new URLSearchParams();
  data.append("currentbrowserversion", "1");
  data.append("currentbrowserversion", "5");
  data.append("currentbrowserversion", "dfadfadfa");

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
