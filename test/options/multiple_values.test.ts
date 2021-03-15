import { OAuth } from "../../mod.ts";
import { base64, HmacSha1 } from "../deps.ts";
import { assertEquals } from "../deps.ts";

function hash_function_SHA1(base_string: string, key: string) {
  const hmac = new HmacSha1(key);
  hmac.update(base_string);
  return base64.encode(hmac.arrayBuffer());
}

Deno.test("Signature method - HMAC-SHA1 signature method with multiple values", () => {
  var oauth = new OAuth({
    consumer: {
      key: "batch-dbc2cd8c-6ca8-463b-96e2-6d8683eac6fd",
      secret: "4S4Rvm25CJZWv7HBg5HOhhlRTBSZ7npl",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
  });

  //overide for testing only !!!
  oauth.getTimeStamp = function () {
    return 1445951836;
  };

  //overide for testing only !!!
  oauth.getNonce = function () {
    return "tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP";
  };

  var request_data = {
    url:
      "http://localhost:3737/rest/profiles/1ea2a42f-e14d-4057-8bcd-3e0b4514a267/properties?alt=json",
    method: "PUT",
    data: {
      currentbrowserversion: ["1", "5", "dfadfadfa"],
      alt: "json",
    },
  };

  var result = oauth.authorize(request_data);

  // Signature should match
  assertEquals(result.oauth_signature, "ri0lfv4udd2uQmkg5cCPVqLruyk=");

  // Nonce should match
  assertEquals(result.oauth_nonce, "tKOQtKan8PHIrIoOlrl17zHkZQ2H5CsP");

  // Timestamp should match
  assertEquals(result.oauth_timestamp, 1445951836);
});
