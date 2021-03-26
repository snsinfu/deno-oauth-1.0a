import * as base64 from "https://deno.land/std@0.91.0/encoding/base64.ts";
import * as sha1 from "https://deno.land/std@0.91.0/hash/sha1.ts";
import * as sha256 from "https://deno.land/std@0.91.0/hash/sha256.ts";

/** The PLAINTEXT signature method. */
export const PLAINTEXT = {
  name: "PLAINTEXT",
  sign: (message: string, key: string): string => key,
};

/** The HMAC-SHA1 signature method. */
export const HMAC_SHA1 = {
  name: "HMAC-SHA1",

  sign: (message: string, key: string): string => {
    const hmac = new sha1.HmacSha1(key);
    hmac.update(message);
    return base64.encode(hmac.arrayBuffer());
  },

  hash: (message: string): string => {
    const hash = new sha1.Sha1();
    hash.update(message);
    return base64.encode(hash.arrayBuffer());
  },
};

/** The HMAC-SHA256 signature method. */
export const HMAC_SHA256 = {
  name: "HMAC-SHA256",

  sign: (message: string, key: string): string => {
    const hmac = new sha256.HmacSha256(key);
    hmac.update(message);
    return base64.encode(hmac.arrayBuffer());
  },

  hash: (message: string): string => {
    const hash = new sha256.Sha256();
    hash.update(message);
    return base64.encode(hash.arrayBuffer());
  },
};
