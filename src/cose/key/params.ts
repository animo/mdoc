export enum CoseKeyParam {
  KeyType = 1,
  KeyID = 2,
  Algorithm = 3,
  KeyOps = 4,
  Curve = -1,
  BaseIV = 5,
  x = -2,
  y = -3,
  d = -4,
  k = -1,
}

export enum JwkParam {
  kty = CoseKeyParam.KeyType,
  kid = CoseKeyParam.KeyID,
  alg = CoseKeyParam.Algorithm,
  key_ops = CoseKeyParam.KeyOps,
  base_iv = CoseKeyParam.BaseIV,
  crv = CoseKeyParam.Curve,
  x = CoseKeyParam.x,
  y = CoseKeyParam.y,
  d = CoseKeyParam.d,
  k = CoseKeyParam.k,
}

export const KtySpecificJwkParams: Record<string, Map<number, string> | undefined> = {
  Ec: new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  Okp: new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  Oct: new Map([[-1, 'k']]),
}

/**
 * Creates a new map with the keys and values of the given map swapped.
 */
export const reverseMap = <K, V>(map: Map<K, V>): Map<V, K> => new Map(Array.from(map).map(([k, v]) => [v, k]))

export const KtySpecificJwkParamsReveverse = Object.fromEntries(
  // biome-ignore lint/style/noNonNullAssertion: <explanation>
  Object.entries(KtySpecificJwkParams).map(([k, v]) => [k, reverseMap(v!)])
)
