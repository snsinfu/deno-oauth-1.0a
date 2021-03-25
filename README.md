# OAuth 1.0a Request Authorization for Deno

[![Test Status][test-badge]][test-url]

OAuth 1.0a Request Authorization module for Deno. [Documentation][doc].

- [Usage](#usage)
- [Test](#test)
- [License](#license)

[test-badge]: https://github.com/snsinfu/deno-oauth-1.0a/workflows/test/badge.svg
[test-url]: https://github.com/snsinfu/deno-oauth-1.0a/actions?query=workflow%3Atest
[doc]: https://doc.deno.land/https/raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/mod.ts

## Usage

[OAuthClient][doc-OAuthClient] object generates HTTP Authorization header for a
request:

```typescript
import * as oauth from "https://raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/mod.ts";

const client = new oauth.OAuthClient({
  consumer: {
    key: "appkey-0123456789abcdef",
    secret: "appsecret-00112233445566778899aabbccddeeff",
  },
  signature: oauth.HMAC_SHA1,
});

const authHeader = client.signToHeader(
  "PATCH",
  "https://api.example.com/profile",
  {
    token: {
      key: "userkey-abcdef0123456789",
      secret: "usersecret-aabbccddeeff00112233445566778899",
    },
    body: new URLSearchParams({ status: "busy" }),
  },
);

console.log("Authorization:", authHeader);
```

[doc-OAuthClient]: https://doc.deno.land/https/raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/mod.ts#OAuthClient

## Test

```console
$ git clone https://github.com/snsinfu/deno-oauth-1.0a
$ cd deno-oauth-1.0a
$ deno test
```

## License

MIT License.

This codebase is a major rework of [ddo/oauth-1.0a][ddo] v2.2.6 in Deno. Design
and many of the tests are inherited from the original work, a copy of which is
kept in the ["original" branch][original].

[ddo]: https://github.com/ddo/oauth-1.0a
[original]: https://github.com/snsinfu/deno-oauth-1.0a/tree/original
