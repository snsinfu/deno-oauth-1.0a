import OAuth from "../mod.ts";
import { assertEquals } from "./deps.ts";

var oauth = new OAuth({
  consumer: {
    key: "",
    secret: "",
  },
});

var request = {
  method: "GET",
  url: "https://api.twitter.com/1/statuses/update.json?&",
};

var oauth_data = {
  oauth_consumer_key: "",
  oauth_nonce: "",
  oauth_signature_method: "",
  oauth_timestamp: 0,
  oauth_version: "",
};

Deno.test("#getParameterString - EmptyGetParam - should be equal to Twitter example", function () {
  assertEquals(oauth.getParameterString(request, oauth_data), "=");
});
