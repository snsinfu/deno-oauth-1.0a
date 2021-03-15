import { OAuth } from "../../mod.ts";
import { base64, HmacSha1 } from "../deps.ts";
import { assertEquals } from "../deps.ts";

function hash_function_SHA1(base_string: string, key: string): string {
  const hmac = new HmacSha1(key);
  hmac.update(base_string);
  return base64.encode(hmac.arrayBuffer());
}

Deno.test("parameter_seperator option - default (', ') - should be equal to Twitter example", () => {
  const oauth = new OAuth({
    consumer: {
      key: "xvz1evFS4wEEPTGEFPHBog",
      secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
  });

  //overide for testing only !!!
  oauth.getTimeStamp = () => {
    return 1318622958;
  };

  //overide for testing only !!!
  oauth.getNonce = () => {
    return "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
  };

  const token = {
    key: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
  };

  const request = {
    url: "https://api.twitter.com/1/statuses/update.json?include_entities=true",
    method: "POST",
    data: {
      status: "Hello Ladies + Gentlemen, a signed OAuth request!",
    },
  };

  assertEquals(
    oauth.toHeader(oauth.authorize(request, token)).Authorization,
    'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version="1.0"',
  );
});

Deno.test("parameter_seperator option - - header should be correct", () => {
  const oauth = new OAuth({
    consumer: {
      key: "xvz1evFS4wEEPTGEFPHBog",
      secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
    parameter_seperator: "-",
  });

  //overide for testing only !!!
  oauth.getTimeStamp = () => {
    return 1318622958;
  };

  //overide for testing only !!!
  oauth.getNonce = () => {
    return "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
  };

  const token = {
    key: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
  };

  const request = {
    url: "https://api.twitter.com/1/statuses/update.json?include_entities=true",
    method: "POST",
    data: {
      status: "Hello Ladies + Gentlemen, a signed OAuth request!",
    },
  };

  assertEquals(
    oauth.toHeader(oauth.authorize(request, token)).Authorization,
    'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog"-oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"-oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D"-oauth_signature_method="HMAC-SHA1"-oauth_timestamp="1318622958"-oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"-oauth_version="1.0"',
  );
});
