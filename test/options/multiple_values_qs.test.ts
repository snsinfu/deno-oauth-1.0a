import OAuth from "../../mod.ts";
import { base64, HmacSha1 } from "../deps.ts";
import { assertEquals } from "../deps.ts";

function hash_function_SHA1(base_string: string, key: string) {
  const hmac = new HmacSha1(key);
  hmac.update(base_string);
  return base64.encode(hmac.arrayBuffer());
}

Deno.test("Signature method - HMAC-SHA1 signature method with multiple duplicate values in the querystring", () => {
  var oauth = new OAuth({
    consumer: {
      key: "batch-8f4fd2c6-9fa3-4368-9797-52876d723dd1",
      secret: "ZACXtYe6LQ4C5X0KbJcDkbW77GYtlaoU",
    },
    signature_method: "HMAC-SHA1",
    hash_function: hash_function_SHA1,
  });

  //overide for testing only !!!
  oauth.getTimeStamp = function () {
    return 1504882975;
  };

  //overide for testing only !!!
  oauth.getNonce = function () {
    return "xsEYfvjTEiPTR3TqJbmhCpUdrDoHF6nk";
  };

  var request_data = {
    url:
      "http://localhost:3737/rest/profiles?property=email&value=vel.arcu%40ultriciesornareelit.ca&property=visitdate&value=abc&alt=json",
    method: "GET",
  };

  var result = oauth.authorize(request_data);

  // Signature should match
  assertEquals(result.oauth_signature, "b6nMehqpHnpx0VlZB9IhqFh4Jq0=");

  // Nonce should match
  assertEquals(result.oauth_nonce, "xsEYfvjTEiPTR3TqJbmhCpUdrDoHF6nk");

  // Timestamp should match
  assertEquals(result.oauth_timestamp, 1504882975);
});
