import * as oauth from "../mod.ts";

export { HMAC_SHA1, HMAC_SHA256, PLAINTEXT } from "../mod.ts";

export class Api {
  private client: oauth.OAuthClient;
  private token?: oauth.Token;
  private realm?: string;
  private baseUrl: string;

  constructor(opts: ApiOptions) {
    this.client = new oauth.OAuthClient(opts);
    this.token = opts.token;
    this.realm = opts.realm;
    this.baseUrl = opts.baseUrl ?? "";
  }

  async request(
    method: string,
    endpoint: string,
    opts?: RequestOptions,
  ): Promise<Response> {
    const url = this.baseUrl + endpoint;

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
    }

    if (opts?.json) {
      body = JSON.stringify(opts.json);
      mime = "application/json";
    }

    const headers = new Headers(opts?.headers);
    if (!headers.has("Content-Type") && mime) {
      headers.set("Content-Type", mime);
    }

    const params = this.client.sign(method, url, {
      token: this.token ?? opts?.token,
      params: opts?.params,
      body: body,
    });
    headers.set("Authorization", oauth.toAuthHeader(params));

    return await fetch(url, { method: method, headers: headers, body: body });
  }
}

export interface ApiOptions {
  consumer: oauth.Token;
  signature: oauth.SignatureMethod;
  token?: oauth.Token;
  realm?: string;
  baseUrl?: string;
}

export interface RequestOptions {
  token?: oauth.Token;
  params?: oauth.OAuthOptions;
  headers?: Headers | Record<string, string>;
  form?: URLSearchParams | Record<string, string>;
  json?: object;
  hashBody?: boolean;
}
