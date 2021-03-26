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

Use [OAuthClient][doc-OAuthClient] object to sign an HTTP request with consumer
and token credentials. You get an `Authorization` header that can be added to an
actual request.

```typescript
import * as oauth from "https://raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/mod.ts";

const client = new oauth.OAuthClient({
  consumer: {
    key: "appkey-0123456789abcdef",
    secret: "appsecret-00112233445566778899aabbccddeeff",
  },
  signature: oauth.HMAC_SHA1,
});

const auth = oauth.toAuthHeader(client.sign(
  "PATCH",
  "https://api.example.com/profile",
  {
    token: {
      key: "userkey-abcdef0123456789",
      secret: "usersecret-aabbccddeeff00112233445566778899",
    },
    body: new URLSearchParams({ status: "busy" }),
  },
));

console.log("Authorization:", auth);
```

[doc-OAuthClient]: https://doc.deno.land/https/raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/mod.ts#OAuthClient

### High-level API

An experimental, high-level module is available in the [extra](./extra)
directory. [Documentation][doc-extra]. Basic usage:

```typescript
import * as oauth from "https://raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/extra/mod.ts";

const api = new oauth.Api({
  prefix: "https://api.example.com/v1",
  consumer: { key: "app-key", secret: "app-secret" },
  signature: oauth.HMAC_SHA1,
});

const response = await api.request("POST", "/review", {
  token: { key: "user-key", secret: "user-secret" },
  json: { book: "c3c24bab", score: 5 },
  hashBody: true,
});
const result = await response.json();
```

[doc-extra]: https://doc.deno.land/https/raw.githubusercontent.com/snsinfu/deno-oauth-1.0a/main/extra/mod.ts

## Test

```console
$ git clone https://github.com/snsinfu/deno-oauth-1.0a
$ cd deno-oauth-1.0a
$ deno test --allow-net=localhost
```

## License

MIT License.

This codebase is a major rework of [ddo/oauth-1.0a][ddo] v2.2.6 in Deno. Design
and many of the tests are inherited from the original work, a copy of which is
kept in the ["original" branch][original].

[ddo]: https://github.com/ddo/oauth-1.0a
[original]: https://github.com/snsinfu/deno-oauth-1.0a/tree/original
