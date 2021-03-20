import { HMAC_SHA1, PLAINTEXT } from "./sign.ts";
import { assertEquals } from "./test_deps.ts";

// PLAINTEXT -----------------------------------------------------------------

Deno.test("PLAINTEXT.name - is correct", () => {
  assertEquals(PLAINTEXT.name, "PLAINTEXT");
});

Deno.test("PLAINTEXT.sign - just returns key", () => {
  assertEquals(PLAINTEXT.sign("message", ""), "");
  assertEquals(PLAINTEXT.sign("message", "key"), "key");
});

// HMAC_SHA1 -----------------------------------------------------------------

Deno.test("HMAC_SHA1.name - is correct", () => {
  assertEquals(HMAC_SHA1.name, "HMAC-SHA1");
});

Deno.test("HMAC_SHA1.sign - returns correct signature", () => {
  // echo -n message | openssl dgst -binary -sha1 -hmac key | base64
  const examples = [
    {
      message: "",
      key: "",
      signature: "+9sdGxiqbAgyS31ktx+3Y3BpDh0=",
    },
    {
      message: "",
      key: "key",
      signature: "9Cuw7rAY671Fl65yE3EexgdghD8=",
    },
    {
      message: "message",
      key: "key",
      signature: "IIjfdNXyFGtIFGyvSWU3fp0L46Q=",
    },
  ];

  for (const { message, key, signature } of examples) {
    assertEquals(HMAC_SHA1.sign(message, key), signature);
  }
});

Deno.test("HMAC_SHA1.hash - returns correct hash", () => {
  // echo -n message | openssl dgst -binary -sha1 | base64
  const examples = [
    {
      message: "",
      hash: "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
    },
    {
      message: "message",
      hash: "b5ua881ui4pzws3O03/p9ZIm4n0=",
    },
  ];

  for (const { message, hash } of examples) {
    assertEquals(HMAC_SHA1.hash(message), hash);
  }
});
