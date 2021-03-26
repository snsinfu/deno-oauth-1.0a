import * as oauth from "../mod.ts";

export { HMAC_SHA1, HMAC_SHA256, PLAINTEXT } from "../mod.ts";
export type { OAuthOptions, SignatureMethod, Token } from "../mod.ts";

/** Class for requesting OAuth-authorized HTTP endpoints. */
export class Api {
  private client: oauth.OAuthClient;
  private realm?: string;
  private prefix: string;

  /**
   * Constructor sets common parameters for authorized HTTP requests.
   *
   * ```ts
   * const api = new Api({
   *   consumer: { key: "app-ynH3TBiW", secret: "JFvg8hoDL3xcOI3D" },
   *   signature: HMAC_SHA1,
   *   prefix: "https://api.example.com",
   * });
   * ```
   *
   * @param opts.consumer - OAuth consumer credential.
   * @param opts.signature - Signature method to use (e.g., `HMAC_SHA1`).
   * @param opts.realm - Optional realm parameter attached to Authorization
   *    header of each request.
   * @param opts.prefix - URL prefix for each request.
   */
  constructor(opts: ApiOptions) {
    this.client = new oauth.OAuthClient(opts);
    this.realm = opts.realm;
    this.prefix = opts.prefix ?? "";
  }

  /**
   * Makes an HTTP request.
   *
   * ```ts
   * const response = await api.request("GET", "/account/me", {
   *   token: { key: "user-N6NfxiK3", secret: "MP2fqEBrmt1MyPkv" },
   * });
   * const data = await response.json();
   * ```
   *
   * @param method - HTTP request method (e.g., "GET").
   * @param endpoint - URL to request, or relative path if `prefix` option has
   *    been set in the constructor.
   * @param opts.token - OAuth token credential used to sign the request.
   * @param opts.params - OAuth parameters to override.
   * @param opts.headers - Extra HTTP headers to send.
   * @param opts.form - Body data. It is sent as a form-encoded string. This
   *    option is mutually exclusive to the `json` option.
   * @param opts.json - Body data. It is sent as a JSON string. This option is
   *    mutually exclusive to the `form` option.
   * @param opts.hashBody - Set to true if you want to attach `oauth_body_hash`
   *    parameter to Authorization header.
   *
   * @return Response.
   */
  async request(
    method: string,
    endpoint: string,
    opts?: RequestOptions,
  ): Promise<Response> {
    const url = this.prefix + endpoint;

    let signBody = false;
    let body: URLSearchParams | string | undefined;
    let mime: string | undefined;

    if (opts?.form && opts?.json) {
      throw new Error("form and json options are mutually exclusive");
    }

    if (opts?.form) {
      body = opts.form instanceof URLSearchParams
        ? opts.form
        : new URLSearchParams(opts.form);
      mime = "application/x-www-form-urlencoded";
      signBody = true;
    }

    if (opts?.json) {
      body = JSON.stringify(opts.json);
      mime = "application/json";
      signBody = opts.hashBody ?? false;
    }

    if (!body && opts?.hashBody) {
      body = "";
      signBody = true;
    }

    const headers = new Headers(opts?.headers);

    if (!headers.has("Content-Type") && mime) {
      headers.set("Content-Type", mime);
    }

    const params = this.client.sign(method, url, {
      token: opts?.token,
      params: opts?.params,
      body: signBody ? body : undefined,
    });
    headers.set("Authorization", oauth.toAuthHeader(params));

    return await fetch(url, { method: method, headers: headers, body: body });
  }
}

/** Options for the Api constructor. */
export interface ApiOptions {
  consumer: oauth.Token;
  signature: oauth.SignatureMethod;
  realm?: string;
  prefix?: string;
}

/** Options for the Api.request() method. */
export interface RequestOptions {
  token?: oauth.Token;
  params?: oauth.OAuthOptions;
  headers?: Headers | Record<string, string>;
  form?: URLSearchParams | Record<string, string>;
  json?: object;
  hashBody?: boolean;
}
