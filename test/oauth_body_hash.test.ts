import { OAuth } from "../mod.ts";
import { assertEquals, assertExists, HmacSha1, Sha1, base64 } from "./deps.ts";

var oauth: OAuth;
var request: any;

function beforeEach() {
  oauth = new OAuth({
    consumer: {
      key: "1434affd-4d69-4a1a-bace-cc5c6fe493bc",
      secret: "932a216f-fb94-43b6-a2d2-e9c6b345cbea",
    },
    signature_method: "HMAC-SHA1",
    hash_function: function (base_string, key) {
      const hmac = new HmacSha1(key);
      hmac.update(base_string);
      return base64.encode(hmac.arrayBuffer());
    },
    body_hash_function: function (data) {
      const hash = new Sha1();
      hash.update(data);
      return base64.encode(hash.arrayBuffer());
    },
  });

  //overide for testing only !!!
  oauth.getTimeStamp = function () {
    return 1484599369;
  };

  //overide for testing only !!!
  oauth.getNonce = function () {
    return "t62lMDp9DLwKZJJbZTpmSAhRINGBEOcF";
  };

  request = {
    url: "http://canvas.docker/api/lti/accounts/1/tool_proxy",
    method: "POST",
    data: {
      "@context": [
        "http://purl.imsglobal.org/ctx/lti/v2/ToolProxy",
      ],
      "@type": "ToolProxy",
      "lti_version": "LTI-2p1",
      "tool_proxy_guid": "0cf04d67-8a0d-4d41-af61-6e8c6fc3e68c",
      "tool_consumer_profile":
        "http://canvas.docker/api/lti/accounts/1/tool_consumer_profile/339b6700-e4cb-47c5-a54f-3ee0064921a9",
      "tool_profile": {
        "lti_version": "LTI-2p1",
        "product_instance": {
          "guid": "fd75124a-140e-470f-944c-114d2d93db40",
          "product_info": {
            "product_name": {
              "default_value": "TestTool",
              "key": "tool.name",
            },
            "product_version": "0.1.0",
            "product_family": {
              "code": "testtool",
              "vendor": {
                "code": "Example.com",
                "vendor_name": {
                  "default_value": "Example",
                  "key": "tool.vendor.name",
                },
              },
            },
          },
        },
        "base_url_choice": [
          {
            "default_base_url": "http://example.docker/",
            "selector": {
              "applies_to": [
                "MessageHandler",
              ],
            },
          },
        ],
        "resource_handler": [
          {
            "resource_type": {
              "code": "testtool",
            },
            "resource_name": {
              "default_value": "TestTool",
              "key": "testtool.resource.name",
            },
            "message": [
              {
                "message_type": "basic-lti-launch-request",
                "path": "lti_launch",
                "enabled_capability": [
                  "Canvas.placements.courseNavigation",
                ],
              },
            ],
          },
        ],
      },
      "enabled_capability": [
        "OAuth.splitSecret",
      ],
      "security_contract": {
        "tp_half_shared_secret":
          "1c7849d3c9f037a9891575c8508d3aaab6a9e1312b5d0353625f83d68f0d545344f81ff9e1849b6400982a0d3f6bf953c6095265e3b6d700a73f5be94ce5654c",
      },
    },
    includeBodyHash: true,
  };
}

Deno.test("OAuth Body Hash - #getBodyHash - should handle data encoded as an object", () => {
  beforeEach();
  assertEquals(oauth.getBodyHash(request, ""), "xpJzRG6xylVIRRtiigLPKX7iRmM=");
});

Deno.test("OAuth Body Hash - #getBodyHash - should handle data encoded as a string", () => {
  beforeEach();
  request.data = "Hello World!";
  assertEquals(oauth.getBodyHash(request, ""), "Lve95gjOVATpfV8EL5X4nxwjKHE=");
});

Deno.test("OAuth Body Hash - #authorize - should properly include an oauth_body_hash param", () => {
  beforeEach();
  assertEquals(oauth.authorize(request), {
    oauth_consumer_key: "1434affd-4d69-4a1a-bace-cc5c6fe493bc",
    oauth_nonce: "t62lMDp9DLwKZJJbZTpmSAhRINGBEOcF",
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: 1484599369,
    oauth_version: "1.0",
    oauth_body_hash: "xpJzRG6xylVIRRtiigLPKX7iRmM=",
    oauth_signature: "1Q0U8yhK1bWYguRxlUDs9KHywOE=",
  });
});

Deno.test("OAuth Body Hash - #toHeader - should properly include an oauth_body_hash header", () => {
  beforeEach();
  const actual = oauth.toHeader(oauth.authorize(request));
  assertExists(actual.Authorization);
  assertEquals(
    actual.Authorization,
    'OAuth oauth_body_hash="xpJzRG6xylVIRRtiigLPKX7iRmM%3D", oauth_consumer_key="1434affd-4d69-4a1a-bace-cc5c6fe493bc", oauth_nonce="t62lMDp9DLwKZJJbZTpmSAhRINGBEOcF", oauth_signature="1Q0U8yhK1bWYguRxlUDs9KHywOE%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1484599369", oauth_version="1.0"',
  );
});
