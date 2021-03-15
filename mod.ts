export class OAuth {
  body_hash_function?: OAuth.BodyHashFunction;
  consumer: OAuth.Consumer;
  hash_function: OAuth.HashFunction;
  last_ampersand: boolean;
  nonce_length: number;
  parameter_seperator: string;
  realm?: string;
  signature_method: string;
  version: string;

  /**
   * Constructor
   * @param {Object} opts consumer key and secret
   */
  constructor(opts: OAuth.Options) {
    if (!opts.consumer) {
      throw new Error("consumer option is required");
    }

    this.consumer = opts.consumer;
    this.nonce_length = opts.nonce_length || 32;
    this.version = opts.version || "1.0";
    this.parameter_seperator = opts.parameter_seperator || ", ";
    this.realm = opts.realm;

    if (typeof opts.last_ampersand === "undefined") {
      this.last_ampersand = true;
    } else {
      this.last_ampersand = opts.last_ampersand;
    }

    // default signature_method is 'PLAINTEXT'
    this.signature_method = opts.signature_method || "PLAINTEXT";

    if (this.signature_method == "PLAINTEXT" && !opts.hash_function) {
      opts.hash_function = function (base_string, key) {
        return key;
      };
    }

    if (!opts.hash_function) {
      throw new Error("hash_function option is required");
    }

    this.hash_function = opts.hash_function;
    this.body_hash_function = opts.body_hash_function || this.hash_function;
  }

  /**
   * OAuth request authorize
   * @param  {Object} request data
   * {
   *     method,
   *     url,
   *     data
   * }
   * @param  {Object} key and secret token
   * @return {Object} OAuth Authorized data
   */
  authorize(
    request: OAuth.RequestOptions,
    token?: OAuth.Token,
  ): OAuth.Authorization {
    var oauth_data: any = {
      oauth_consumer_key: this.consumer.key,
      oauth_nonce: this.getNonce(),
      oauth_signature_method: this.signature_method,
      oauth_timestamp: this.getTimeStamp(),
      oauth_version: this.version,
    };

    if (token?.key !== undefined) {
      oauth_data.oauth_token = token.key;
    }

    if (!request.data) {
      request.data = {};
    }

    if (request.includeBodyHash) {
      oauth_data.oauth_body_hash = this.getBodyHash(request, token?.secret);
    }

    oauth_data.oauth_signature = this.getSignature(
      request,
      token?.secret,
      oauth_data,
    );

    return oauth_data;
  }

  /**
   * Create a OAuth Signature
   * @param  {Object} request data
   * @param  {Object} token_secret key and secret token
   * @param  {Object} oauth_data   OAuth data
   * @return {String} Signature
   */
  getSignature(
    request: OAuth.RequestOptions,
    token_secret: string | undefined,
    oauth_data: OAuth.Data,
  ): string {
    return this.hash_function(
      this.getBaseString(request, oauth_data),
      this.getSigningKey(token_secret),
    );
  }

  /**
   * Create a OAuth Body Hash
   * @param {Object} request data
   */
  getBodyHash(
    request: OAuth.RequestOptions,
    token_secret: string | undefined,
  ): string {
    var body = typeof request.data === "string"
      ? request.data
      : JSON.stringify(request.data);

    if (!this.body_hash_function) {
      throw new Error("body_hash_function option is required");
    }

    return this.body_hash_function(body, this.getSigningKey(token_secret));
  }

  /**
   * Base String = Method + Base Url + ParameterString
   * @param  {Object} request data
   * @param  {Object} OAuth data
   * @return {String} Base String
   */
  getBaseString(request: OAuth.RequestOptions, oauth_data: OAuth.Data): string {
    return request.method.toUpperCase() + "&" +
      this.percentEncode(this.getBaseUrl(request.url)) + "&" +
      this.percentEncode(this.getParameterString(request, oauth_data));
  }

  /**
   * Get data from url
   * -> merge with oauth data
   * -> percent encode key & value
   * -> sort
   *
   * @param  {Object} request data
   * @param  {Object} OAuth data
   * @return {Object} Parameter string data
   */
  getParameterString(
    request: OAuth.RequestOptions,
    oauth_data: OAuth.Data,
  ): string {
    var base_string_data;
    if (oauth_data.oauth_body_hash) {
      base_string_data = this.sortObject(
        this.percentEncodeData(
          this.mergeObject(oauth_data, this.deParamUrl(request.url)),
        ),
      );
    } else {
      base_string_data = this.sortObject(
        this.percentEncodeData(
          this.mergeObject(
            oauth_data,
            this.mergeObject(request.data, this.deParamUrl(request.url)),
          ),
        ),
      );
    }

    var data_str = "";

    //base_string_data to string
    for (var i = 0; i < base_string_data.length; i++) {
      var key = base_string_data[i].key.toString();
      var value = base_string_data[i].value;
      // check if the value is an array
      // this means that this key has multiple values
      if (value && Array.isArray(value)) {
        // sort the array first
        value.sort();

        var valString = "";
        // serialize all values for this key: e.g. formkey=formvalue1&formkey=formvalue2
        value.forEach((function (item: string, i: number) {
          valString += key + "=" + item;
          if (i < value.length) {
            valString += "&";
          }
        }).bind(this));
        data_str += valString;
      } else {
        data_str += key + "=" + value + "&";
      }
    }

    //remove the last character
    data_str = data_str.substr(0, data_str.length - 1);
    return data_str;
  }

  /**
   * Create a Signing Key
   * @param  {String} token_secret Secret Token
   * @return {String} Signing Key
   */
  getSigningKey(token_secret: string | undefined): string {
    token_secret = token_secret || "";

    if (!this.last_ampersand && !token_secret) {
      return this.percentEncode(this.consumer.secret);
    }

    return this.percentEncode(this.consumer.secret) + "&" +
      this.percentEncode(token_secret);
  }

  /**
   * Get base url
   * @param  {String} url
   * @return {String}
   */
  getBaseUrl(url: string): string {
    return url.split("?")[0];
  }

  /**
   * Get data from String
   * @param  {String} string
   * @return {Object}
   */
  deParam(str: string): OAuth.Param {
    var arr = str.split("&");
    var data: any = {};

    for (var i = 0; i < arr.length; i++) {
      var item = arr[i].split("=");

      // '' value
      item[1] = item[1] || "";

      // check if the key already exists
      // this can occur if the QS part of the url contains duplicate keys like this: ?formkey=formvalue1&formkey=formvalue2
      if (data[item[0]]) {
        // the key exists already
        if (!Array.isArray(data[item[0]])) {
          // replace the value with an array containing the already present value
          data[item[0]] = [data[item[0]]];
        }
        // and add the new found value to it
        data[item[0]].push(decodeURIComponent(item[1]));
      } else {
        // it doesn't exist, just put the found value in the data object
        data[item[0]] = decodeURIComponent(item[1]);
      }
    }

    return data;
  }

  /**
   * Get data from url
   * @param  {String} url
   * @return {Object}
   */
  deParamUrl(url: string): OAuth.Param {
    var tmp = url.split("?");

    if (tmp.length === 1) {
      return {};
    }

    return this.deParam(tmp[1]);
  }

  /**
   * Percent Encode
   * @param  {String} str
   * @return {String} percent encoded string
   */
  percentEncode(str: string): string {
    return encodeURIComponent(str)
      .replace(/\!/g, "%21")
      .replace(/\*/g, "%2A")
      .replace(/\'/g, "%27")
      .replace(/\(/g, "%28")
      .replace(/\)/g, "%29");
  }

  /**
   * Percent Encode Object
   * @param  {Object} data
   * @return {Object} percent encoded data
   */
  percentEncodeData(data: any): any {
    var result: any = {};

    for (var key in data) {
      var value = data[key];
      // check if the value is an array
      if (value && Array.isArray(value)) {
        var newValue: string[] = [];
        // percentEncode every value
        value.forEach((val: any) => {
          newValue.push(this.percentEncode(val as string));
        });
        value = newValue;
      } else {
        value = this.percentEncode(value);
      }
      result[this.percentEncode(key)] = value;
    }

    return result;
  }

  /**
   * Get OAuth data as Header
   * @param  {Object} oauth_data
   * @return {String} Header data key - value
   */
  toHeader(oauth_data: OAuth.Authorization): OAuth.Header {
    var sorted = this.sortObject(oauth_data);

    var header_value = "OAuth ";

    if (this.realm) {
      header_value += 'realm="' + this.realm + '"' + this.parameter_seperator;
    }

    for (var i = 0; i < sorted.length; i++) {
      if ((sorted[i].key as string).indexOf("oauth_") !== 0) {
        continue;
      }

      header_value += this.percentEncode(sorted[i].key) + '="' +
        this.percentEncode(sorted[i].value as string) + '"' +
        this.parameter_seperator;
    }

    return {
      Authorization: header_value.substr(
        0,
        header_value.length - this.parameter_seperator.length,
      ), //cut the last chars
    };
  }

  /**
   * Create a random word characters string with input length
   * @return {String} a random word characters string
   */
  getNonce(): string {
    var word_characters =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var result = "";

    for (var i = 0; i < this.nonce_length; i++) {
      result += word_characters[(Math.random() * word_characters.length) >> 0];
    }

    return result;
  }

  /**
   * Get Current Unix TimeStamp
   * @return {Int} current unix timestamp
   */
  getTimeStamp(): number {
    return (Date.now() / 1000) >> 0;
  }

  ////////////////////// HELPER FUNCTIONS //////////////////////

  /**
   * Merge object
   * @param  {Object} obj1
   * @param  {Object} obj2
   * @return {Object}
   */
  mergeObject<T extends object, U extends object>(obj1: T, obj2: U): T & U {
    return Object.assign({}, obj1, obj2);
  }

  /**
   * Sort object by key
   * @param  {Object} data
   * @return {Array} sorted array
   */
  sortObject<O extends { [k: string]: any }, K extends string>(
    obj: O,
  ): Array<{ key: keyof O; value: O[K] }> {
    var keys = Object.keys(obj);
    var result = [];

    keys.sort();

    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      result.push({
        key: key,
        value: obj[key],
      });
    }

    return result;
  }
}

export namespace OAuth {
  /**
   * OAuth data, including the signature.
   */
  export interface Authorization extends Data {
    oauth_signature: string;
  }

  /**
   * Method used to generate the body hash.
   *
   * Note: the key is used for implementation HMAC algorithms for the body hash,
   * but typically it should return SHA1 hash of base_string.
   */
  export type BodyHashFunction = (base_string: string, key: string) => string;

  /**
   * OAuth key/secret pair.
   */
  export interface Consumer {
    key: string;
    secret: string;
  }

  /**
   * OAuth data, excluding the signature.
   */
  export interface Data {
    oauth_consumer_key: string;
    oauth_nonce: string;
    oauth_signature_method: string;
    oauth_timestamp: number;
    oauth_version: string;
    oauth_token?: string;
    oauth_body_hash?: string;
  }

  /**
   * Method used to hash the the OAuth and form/querystring data.
   */
  export type HashFunction = (base_string: string, key: string) => string;

  /**
   * Authorization header.
   */
  export interface Header {
    Authorization: string;
  }

  /**
   * OAuth options.
   */
  export interface Options {
    body_hash_function?: BodyHashFunction;
    consumer: Consumer;
    hash_function?: HashFunction;
    last_ampersand?: boolean;
    nonce_length?: number;
    parameter_seperator?: string;
    realm?: string;
    signature_method?: string;
    version?: string;
  }

  /**
   * Extra data.
   */
  export interface Param {
    [key: string]: string | string[];
  }

  /**
   * Request options.
   */
  export interface RequestOptions {
    url: string;
    method: string;
    data?: any;
    includeBodyHash?: boolean;
  }

  /**
   * OAuth token key/secret pair.
   */
  export interface Token {
    key: string;
    secret: string;
  }
}

export default OAuth;
