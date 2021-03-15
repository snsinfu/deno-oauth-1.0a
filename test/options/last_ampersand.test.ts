import { OAuth } from "../../mod.ts";
import { base64, HmacSha1 } from "../deps.ts";
import { assertEquals } from "../deps.ts";

function hash_function_SHA1(base_string: string, key: string): string {
  const hmac = new HmacSha1(key);
  hmac.update(base_string);
  return base64.encode(hmac.arrayBuffer());
}

(() => {
  const oauth = new OAuth({
    consumer: {
      key: "",
      secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
  });

  const token = {
    secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
  };

  Deno.test("last_ampersand option - default (true) - should be equal to Twitter example", () => {
    assertEquals(
      oauth.getSigningKey(token.secret),
      "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
    );
  });

  Deno.test("last_ampersand option - default (true) - should has the ampersand at the end", () => {
    assertEquals(
      oauth.getSigningKey(undefined),
      "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&",
    );
  });
})();

(() => {
  const oauth = new OAuth({
    consumer: {
      key: "",
      secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
    last_ampersand: false,
  });

  const token = {
    secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
  };

  Deno.test("last_ampersand option - change to false - should be equal to Twitter example", () => {
    assertEquals(
      oauth.getSigningKey(token.secret),
      "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
    );
  });

  Deno.test("last_ampersand option - change to false - should not has the ampersand at the end", () => {
    assertEquals(
      oauth.getSigningKey(undefined),
      "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    );
  });
})();
