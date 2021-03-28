import * as oauth from "../mod.ts";

export { HMAC_SHA1, HMAC_SHA256, PLAINTEXT } from "../mod.ts";
export type { OAuthOptions, SignatureMethod, Token } from "../mod.ts";

/** Class for requesting OAuth-authorized HTTP endpoints. */
export class Api {
  private client: oauth.OAuthClient;
  private realm?: string;

  /** URL prefix passed to the constructor (if any). */
  readonly prefix: string;

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
   * @param opts.query - Query parameters to append to the URL.
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
    // Compose URL. Here, we want the prefix to just be prepended to the URL,
    // so do not use the `base` option of the URL constructor.
    const url = new URL(this.prefix + endpoint);

    if (opts?.query) {
      const extraQuery = opts.query instanceof URLSearchParams
        ? opts.query
        : new URLSearchParams(opts.query);
      const extraQueryString = extraQuery.toString();

      if (extraQueryString.length > 0) {
        if (url.search.length > 0) {
          url.search = url.search + "&" + extraQueryString;
        } else {
          url.search = extraQueryString;
        }
      }
    }

    // Encode body data. Note that JSON body should be sent unsigned if hashBody
    // is explicitly set to true. In that case, we do not pass the body to the
    // OAuthClient but still send it to the URL.
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

    // Compose headers.
    const headers = new Headers(opts?.headers);

    if (!headers.has("Content-Type") && mime) {
      headers.set("Content-Type", mime);
    }

    const params = this.client.sign(method, url.toString(), {
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
  query?: URLSearchParams | Record<string, string>;
  form?: URLSearchParams | Record<string, string>;
  json?: object;
  hashBody?: boolean;
}
