import { HMAC_SHA1, HMAC_SHA256, PLAINTEXT } from "./sign.ts";
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

// HMAC_SHA256 ---------------------------------------------------------------

Deno.test("HMAC_SHA256.name - is correct", () => {
  assertEquals(HMAC_SHA256.name, "HMAC-SHA256");
});

Deno.test("HMAC_SHA256.sign - returns correct signature", () => {
  // echo -n message | openssl dgst -binary -sha256 -hmac key | base64
  const examples = [
    {
      message: "",
      key: "",
      signature: "thNnmggU2ex3L5XXeMNfxf8Wl8STcVZTxscSFEKSxa0=",
    },
    {
      message: "",
      key: "key",
      signature: "XV0TlWPJW1lnub2ajJsjOp3ttFByeUzSMtwbdIMmB9A=",
    },
    {
      message: "message",
      key: "key",
      signature: "bp7ym3X//Ft6uuUn1Y/a2y/kLnIZARl2kXNDBl9Y7Uo=",
    },
  ];

  for (const { message, key, signature } of examples) {
    assertEquals(HMAC_SHA256.sign(message, key), signature);
  }
});

Deno.test("HMAC_SHA256.hash - returns correct hash", () => {
  // echo -n message | openssl dgst -binary -sha256 | base64
  const examples = [
    {
      message: "",
      hash: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    },
    {
      message: "message",
      hash: "q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=",
    },
  ];

  for (const { message, hash } of examples) {
    assertEquals(HMAC_SHA256.hash(message), hash);
  }
});
