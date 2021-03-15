import OAuth from "../../mod.ts";
import { assertEquals, assertThrows } from "../deps.ts";

Deno.test("Signature method - default PLAINTEXT signature method", () => {
  var oauth = new OAuth({
    consumer: { key: "", secret: "" },
  });

  assertEquals(oauth.signature_method, "PLAINTEXT");
});

Deno.test("Signature method - default PLAINTEXT hash function - hash should return key only", () => {
  var oauth = new OAuth({
    consumer: { key: "", secret: "" },
    signature_method: "PLAINTEXT",
  });

  assertEquals(oauth.hash_function("base_string", "key"), "key");
});

Deno.test("missing hash function - constructor should throw a error", () => {
  assertThrows(
    function () {
      new OAuth(
        {
          consumer: {key: "", secret: ""},
          signature_method: "RSA-SHA1",
        },
      );
    },
    undefined,
    undefined,
    "hash_function option is required",
  );
});
