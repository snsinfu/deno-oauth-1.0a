import { OAuth } from "../../mod.ts";
import { assertEquals } from "../deps.ts";

//TODO: check alphabet and numberic only

Deno.test("nonce_length option - default (32) - nonce length should be 32", () => {
  var oauth = new OAuth({
    consumer: { key: "", secret: "" },
  });

  assertEquals(oauth.getNonce().length, 32);
});

Deno.test("nonce_length option - length 100 - nonce length should be 100", () => {
  var oauth = new OAuth({
    consumer: { key: "", secret: "" },
    nonce_length: 100,
  });

  assertEquals(oauth.getNonce().length, 100);
});

Deno.test("nonce_length option - random length - nonce length should be correct", () => {
  var random = (Math.random() * 100) >> 0;

  while (random === 0) {
    random = (Math.random() * 100) >> 0;
  }

  var oauth = new OAuth({
    consumer: { key: "", secret: "" },
    nonce_length: random,
  });

  assertEquals(oauth.getNonce().length, random);
});
