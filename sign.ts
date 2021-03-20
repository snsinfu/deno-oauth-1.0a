import * as base64 from "https://deno.land/std@0.90.0/encoding/base64.ts";
import { HmacSha1, Sha1 } from "https://deno.land/std@0.90.0/hash/sha1.ts";

/** The PLAINTEXT signature method. */
export const PLAINTEXT = {
  name: "PLAINTEXT",
  sign: (message: string, key: string): string => key,
};

/** The HMAC-SHA1 signature method. */
export const HMAC_SHA1 = {
  name: "HMAC-SHA1",

  sign: (message: string, key: string): string => {
    const hmac = new HmacSha1(key);
    hmac.update(message);
    return base64.encode(hmac.arrayBuffer());
  },

  hash: (message: string): string => {
    const hash = new Sha1();
    hash.update(message);
    return base64.encode(hash.arrayBuffer());
  },
};
