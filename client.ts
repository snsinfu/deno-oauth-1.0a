/** Default nonce string length. */
const nonceLength = 32;

/**
 * OAuth 1.0a client.
 *
 * A client object does not send actual request to a server. Its task is to
 * compute OAuth parameters (or an Authorization header) for you.
 */
export class OAuthClient {
  private consumer: Token;
  private signature: SignatureMethod;
  private realm?: string;

  /**
   * Constructor sets common parameters for signing requests.
   *
   * @param opts.consumer - Consumer token (sometimes called app token).
   * @param opts.signature - Signature method to use.
   * @param opts.realm - The realm parameter used to generate Authorization
   *    header in the signToHeader method. Default is not to use realm.
   */
  constructor(opts: ClientOptions) {
    this.consumer = opts.consumer;
    this.signature = opts.signature;
    this.realm = opts.realm;
  }

  /**
   * Signs a request.
   *
   * @param method - HTTP method.
   * @param url - URL to request. This may contain query parameters.
   * @param opts.token - Request token (token for an authorized user).
   * @param opts.params - Overriden OAuth parameters. You can set special
   *    protocol parameters like oauth_callback or specify oauth_timestamp
   *    and oauth_nonce for testing.
   * @param opts.body - Request body to sign. If you will send a form-encoded
   *    body, you MUST pass it as a URLSearchParams object; it's signed along
   *    with other OAuth parameters as mandated by the standard. Otherwise,
   *    you MAY pass a stringified body. Then, the string is hashed and an
   *    oauth_body_hash parameter (which is an extension) is added to the
   *    signed parameters. Omit this option if you do not want a body hash.
   *
   * @return Signed OAuth protocol parameters as a SignedOAuthParams object.
   *    The result can be converted to an Authorization header (toAuthHeader),
   *    query parameters or form-encoded body (toQueryParams).
   *
   * @see signToHeader
   */
  sign(method: string, url: string, opts?: SignOptions): SignedOAuthParams {
    const params: OAuthParams = {
      oauth_consumer_key: this.consumer.key,
      oauth_signature_method: this.signature.name,
      ...opts?.params,
    };

    if (opts?.token) {
      params.oauth_token = opts.token.key;
    }

    // oauth_body_hash extension.
    // https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html
    if (typeof opts?.body === "string") {
      if (!this.signature.hash) {
        throw new Error("hash function is required to sign non-form body");
      }
      params.oauth_body_hash = this.signature.hash(opts.body as string);
    }

    if (!params.oauth_timestamp) {
      params.oauth_timestamp = generateTimestamp();
    }

    if (!params.oauth_nonce) {
      params.oauth_nonce = generateNonce(nonceLength);
    }

    const { baseUrl, query } = splitQueryString(url);
    const baseParams = createBaseParams(
      params,
      query ? new URLSearchParams(query) : undefined,
      opts?.body instanceof URLSearchParams ? opts.body : undefined,
    );
    const baseString = createBaseString(method, baseUrl, baseParams);
    const key = percentEncode(this.consumer.secret) + "&" +
      percentEncode(opts?.token?.secret ?? "");
    const signature = this.signature.sign(baseString, key);

    return { oauth_signature: signature, ...params };
  }

  /**
   * Signs a request and returns an Authorization header. This method is
   * equivalent to calling toAuthHeader() on the return value of the sign()
   * method.
   */
  signToHeader(method: string, url: string, opts?: SignOptions): string {
    return toAuthHeader(this.sign(method, url, opts), this.realm);
  }
}

/** Options for Client constructor. */
export interface ClientOptions {
  consumer: Token;
  signature: SignatureMethod;
  realm?: string;
}

/** Represents an OAuth token credential. */
export interface Token {
  key: string;
  secret: string;
}

/** Represents a signature method. */
export interface SignatureMethod {
  name: string;
  sign: (message: string, key: string) => string;
  hash?: (message: string) => string;
}

/** Options for the Client.sign() method. */
export interface SignOptions {
  token?: Token;
  params?: OAuthOptions;
  body?: URLSearchParams | string;
}

/** Collection of user-overridable OAuth protocol parameters. */
export interface OAuthOptions {
  oauth_verifier?: string;
  oauth_callback?: string;
  oauth_timestamp?: number;
  oauth_nonce?: string;
  oauth_version?: "1.0";
}

/** Collection of OAuth protocol parameters except signature. */
export interface OAuthParams {
  oauth_consumer_key: string;
  oauth_token?: string;
  oauth_verifier?: string;
  oauth_callback?: string;
  oauth_timestamp?: number;
  oauth_nonce?: string;
  oauth_version?: "1.0";
  oauth_signature_method?: string;
  oauth_body_hash?: string;
}

/**
 * Collection of OAuth protocol parameters including signature.
 */
export interface SignedOAuthParams extends OAuthParams {
  oauth_signature: string;
}

/**
 * Composes HTTP Authorization header.
 *
 * @param params - OAuth protocol parameters with signature.
 * @param realm - Optional realm parameter attached to the header.
 *
 * @return The content of OAuth Authorization header. The parameters are sorted
 *    as described in the RFC.
 */
export function toAuthHeader(
  params: SignedOAuthParams,
  realm?: string,
): string {
  let header = "OAuth ";
  let count = 0;

  if (realm) {
    // realm is encoded as an HTTP quoted-string (RFC 7230 3.2.6).
    const quotable = realm
      .replace(/\\/g, "\\\\")
      .replace(/\"/g, '\\"');
    header += `realm="${quotable}"`;
    count++;
  }

  // Normalize parameters. This is not strictly necessary (only percent encoding
  // is required), but the consistent ordering is useful for testing.
  const paramsKv = normalizeParams(createBaseParams(params));

  for (const { key, value } of paramsKv) {
    if (count > 0) {
      header += ", ";
    }
    header += `${key}="${value}"`;
    count++;
  }

  return header;
}

/**
 * Composes URL query parameters or a form-encoded body.
 *
 * @param params - OAuth protocol parameters with signature.
 *
 * @return The parameters stored in a URLSearchParams object. The parameters
 *    are sorted as described in the RFC.
 */
export function toQueryParams(params: SignedOAuthParams): URLSearchParams {
  const query = new URLSearchParams();
  const paramsKv = normalizeParams(createBaseParams(params));

  for (const { key, value } of paramsKv) {
    // This looks dumb, but to get a consistent ordering of parameters, we need
    // to normalize (encode + sort) the parameters and then decode the result.
    query.append(decodeURIComponent(key), decodeURIComponent(value));
  }

  return query;
}

/** Generates the current timestamp. */
function generateTimestamp(): number {
  return (Date.now() / 1000) | 0;
}

/** Generates a random nonce string of specified length. */
function generateNonce(length: number): string {
  const wordCharacters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";

  for (let i = 0; i < length; i++) {
    result += wordCharacters[(Math.random() * wordCharacters.length) | 0];
  }

  return result;
}

/**
 * Splits an URL into base string URI (per 3.4.1.2) and query string component.
 */
function splitQueryString(url: string): { baseUrl: string; query?: string } {
  const pos = url.indexOf("?");
  if (pos === -1) {
    return { baseUrl: url };
  }
  return { baseUrl: url.substr(0, pos), query: url.substr(pos + 1) };
}

/**
 * Percent-encodes string per 3.6. We cannot just use encodeURIComponent because
 * it does not escape characters "!*'()" which must be escaped in OAuth.
 */
function percentEncode(str: string): string {
  return encodeURIComponent(str)
    .replace(/\!/g, "%21")
    .replace(/\*/g, "%2A")
    .replace(/\'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29");
}

/**
 * KV represents a single request parameter. Because OAuth request parameters
 * are ordered and may contain duplicate keys, it is better to use an array of
 * key-value pairs instead of a map to store request parameters.
 */
export interface KV {
  key: string;
  value: string;
}

/**
 * Collects request parameters per 3.4.1.3.
 *
 * @param params - OAuth protocol parameters. This can be any object that
 *    extends the OAuthParams interface. Extra parameters are stringified and
 *    appended to the result.
 * @param query - URL query parameters.
 * @param body - Form-encoded request body.
 *
 * @return Array of the collected parameters.
 */
export function createBaseParams(
  params: OAuthParams,
  query?: URLSearchParams,
  body?: URLSearchParams,
): KV[] {
  const paramsKV = Object.entries(params).map(
    ([key, value]: [string, any]) => ({ key, value: value.toString() }),
  );

  const queryKV = !query ? [] : Array.from(query.entries()).map(
    ([key, value]: [string, string]) => ({ key, value }),
  );

  const bodyKV = !body ? [] : Array.from(body.entries()).map(
    ([key, value]: [string, string]) => ({ key, value }),
  );

  return paramsKV.concat(queryKV, bodyKV);
}

/**
 * Creates signature base string per 3.4.1.1.
 *
 * @param method - HTTP request method.
 * @param baseUrl - HTTP URL without query component.
 * @param params - Request parameters to sign. See createBaseParams().
 *
 * @return Signature base string.
 */
export function createBaseString(
  method: string,
  baseUrl: string,
  params: KV[],
): string {
  const paramStr = normalizeParams(params)
    .map(({ key, value }: KV) => key + "=" + value)
    .join("&");
  return percentEncode(method.toUpperCase()) + "&" +
    percentEncode(baseUrl) + "&" +
    percentEncode(paramStr);
}

/** Normalize request parameters per 3.4.1.3.2. */
function normalizeParams(params: KV[]): KV[] {
  const encoded = params.map((param: KV): KV => ({
    key: percentEncode(param.key),
    value: percentEncode(param.value),
  }));
  return encoded.sort((a: KV, b: KV): number => {
    const ax = [a.key, a.value];
    const bx = [b.key, b.value];
    return ax < bx ? -1 : ax > bx ? 1 : 0;
  });
}
