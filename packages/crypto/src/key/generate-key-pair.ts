import type { CryptoContext } from '../c-crypto.js';
import { generateKeyPair as generate } from '../generate.js';

export interface GenerateKeyPairResult {
  /** The generated Private Key. */
  privateKey: CryptoKey;

  /** Public Key corresponding to the generated Private Key. */
  publicKey: CryptoKey;
}

export interface GenerateKeyPairOptions {
  /**
   * The EC "crv" (Curve) or OKP "crv" (Subtype of Key Pair) value to generate. The curve must be
   * both supported on the runtime as well as applicable for the given JWA algorithm identifier.
   */
  crv?: string;

  /**
   * A hint for RSA algorithms to generate an RSA key of a given `modulusLength` (Key size in bits).
   * JOSE requires 2048 bits or larger. Default is 2048.
   */
  modulusLength?: number;

  /**
   * (Only effective in Web Crypto API runtimes) The value to use as
   * {@link !SubtleCrypto.generateKey} `extractable` argument. Default is false.
   *
   * @example
   *
   * ```js
   * const { publicKey, privateKey } = await jose.generateKeyPair('PS256', {
   *   extractable: true,
   * })
   * console.log(await jose.exportJWK(privateKey))
   * console.log(await jose.exportPKCS8(privateKey))
   * ```
   */
  extractable?: boolean;
}

/**
 * Generates a private and a public key for a given JWA algorithm identifier. This can only generate
 * asymmetric key pairs. For symmetric secrets use the `generateSecret` function.
 *
 * Note: Under Web Crypto API runtime the `privateKey` is generated with `extractable` set to
 * `false` by default. See {@link extractable} to generate an extractable
 * `privateKey`.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/generate/keypair'`.
 *
 * @example
 *
 * ```js
 * const { publicKey, privateKey } = await jose.generateKeyPair('PS256')
 * console.log(publicKey)
 * console.log(privateKey)
 * ```
 *
 * @param alg JWA Algorithm Identifier to be used with the generated key pair.
 * @param options Additional options passed down to the key pair generation.
 */
export async function generateKeyPair(
  input: {
    alg: string;
  } & GenerateKeyPairOptions,
  ctx?: CryptoContext
): Promise<GenerateKeyPairResult> {
  return generate(input, ctx);
}
