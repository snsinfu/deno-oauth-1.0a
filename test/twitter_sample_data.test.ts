import OAuth from "../mod.ts";
import { assertEquals, assertExists, base64, HmacSha1 } from "./deps.ts";

var oauth = new OAuth({
  consumer: {
    key: "xvz1evFS4wEEPTGEFPHBog",
    secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
  },
  signature_method: "HMAC-SHA1",
  hash_function: function (base_string, key) {
    const hmac = new HmacSha1(key);
    hmac.update(base_string);
    return base64.encode(hmac.arrayBuffer());
  },
});

//overide for testing only !!!
oauth.getTimeStamp = function () {
  return 1318622958;
};

//overide for testing only !!!
oauth.getNonce = function () {
  return "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
};

var token = {
  key: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
  secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
};

var request = {
  url: "https://api.twitter.com/1/statuses/update.json?include_entities=true",
  method: "POST",
  data: {
    status: "Hello Ladies + Gentlemen, a signed OAuth request!",
  },
};

var oauth_data = {
  oauth_consumer_key: oauth.consumer.key,
  oauth_nonce: oauth.getNonce(),
  oauth_signature_method: oauth.signature_method,
  oauth_timestamp: oauth.getTimeStamp(),
  oauth_version: "1.0",
  oauth_token: token.key,
};

Deno.test("Twitter Sample - #getParameterString - should be equal to Twitter example", () => {
  assertEquals(
    oauth.getParameterString(request, oauth_data),
    "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21",
  );
});

Deno.test("Twitter Sample - #getBaseString - should be equal to Twitter example", () => {
  assertEquals(
    oauth.getBaseString(request, oauth_data),
    "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521",
  );
});

Deno.test("Twitter Sample - #getSigningKey - should be equal to Twitter example", () => {
  assertEquals(
    oauth.getSigningKey(token.secret),
    "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
  );
});

Deno.test("Twitter Sample - #getSignature - should be equal to Twitter example", () => {
  assertEquals(
    oauth.getSignature(request, token.secret, oauth_data),
    "tnnArxj06cWHq44gCs1OSKk/jLY=",
  );
});

Deno.test("Twitter Sample - #authorize - should be equal to Twitter example", () => {
  assertEquals(oauth.authorize(request, token), {
    oauth_consumer_key: "xvz1evFS4wEEPTGEFPHBog",
    oauth_nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: 1318622958,
    oauth_version: "1.0",
    oauth_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    oauth_signature: "tnnArxj06cWHq44gCs1OSKk/jLY=",
  });
});

Deno.test("Twitter Sample - #toHeader - should be equal to Twitter example", () => {
  const actual = oauth.toHeader(oauth.authorize(request, token));
  assertExists(actual.Authorization);
  assertEquals(
    actual.Authorization,
    'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version="1.0"',
  );
});
