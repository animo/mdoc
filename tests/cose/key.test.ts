import { describe, expect, test } from 'vitest'
import { CoseKey, SignatureAlgorithm } from '../../src'
import { Curve } from '../../src/cose/key/curve'
import { KeyOps } from '../../src/cose/key/key-operation'
import { KeyType } from '../../src/cose/key/key-type'
import { base64url } from '../../src/utils'

describe('cose key', () => {
  test('create ec key instance', () => {
    const key = new CoseKey({
      keyType: KeyType.Ec,
    })

    expect(key.keyType).toStrictEqual(KeyType.Ec)
    expect(key.x).toBeUndefined()
    expect(key.y).toBeUndefined()
    expect(key.d).toBeUndefined()
    expect(() => key.publicKey).toThrow()
    expect(() => key.privateKey).toThrow()
  })

  test('create ec key instance with public key', () => {
    const key = new CoseKey({
      keyType: KeyType.Ec,
      curve: Curve['P-256'],
      keyOps: [KeyOps.Verify],
      x: base64url.decode('TgXwg173AdoB8XPXrF6d9QomYdvSFiMDM0vGH3pbvSw'),
      y: base64url.decode('RvP1wJCz8Bcywp9KGXE3UxtnMK4h-BU0j12XLPsxM4Y'),
    })

    expect(key.keyType).toStrictEqual(KeyType.Ec)
    expect(key.keyOps).toStrictEqual([KeyOps.Verify])
    expect(key.curve).toStrictEqual(Curve['P-256'])
    expect(key.x).toBeDefined()
    expect(key.y).toBeDefined()
    expect(key.d).toBeUndefined()
    expect(base64url.encode(key.publicKey)).toStrictEqual(
      'BE4F8INe9wHaAfFz16xenfUKJmHb0hYjAzNLxh96W70sRvP1wJCz8Bcywp9KGXE3UxtnMK4h-BU0j12XLPsxM4Y'
    )
  })

  test('create ec key instance with private key', () => {
    const key = new CoseKey({
      keyType: KeyType.Ec,
      curve: Curve['P-256'],
      keyOps: [KeyOps.Sign],
      d: base64url.decode('wOSo__ixR1AmrohLvcXpy-q5cK28TFwb4cDasS-qEZo'),
    })

    expect(key.keyType).toStrictEqual(KeyType.Ec)
    expect(key.keyOps).toStrictEqual([KeyOps.Sign])
    expect(key.curve).toStrictEqual(Curve['P-256'])
    expect(key.x).toBeUndefined()
    expect(key.y).toBeUndefined()
    expect(key.d).toBeDefined()
    expect(base64url.encode(key.privateKey)).toStrictEqual('wOSo__ixR1AmrohLvcXpy-q5cK28TFwb4cDasS-qEZo')
  })

  test('create cose key from jwk', () => {
    const jwk = {
      kty: 'EC',
      d: 'hGc90b8KMIjIpZos81yEFbOMc0Ww3k5ZNWICzDwtFV4',
      use: 'sig',
      crv: 'P-256',
      x: 'eBUFGSPkdYwJ9TqYpcNxhAyr-A8wlWzrLQJppSi3x0E',
      y: 'Jnf8v4steg6Gr4IEFpg_xcM5xdHKdngbQN9ERJbJvl8',
      alg: 'ES256',
    }

    const coseKey = CoseKey.fromJwk(jwk)

    expect(coseKey.keyType).toBeDefined()
    expect(coseKey.curve).toStrictEqual(Curve['P-256'])
    expect(coseKey.algorithm).toStrictEqual(SignatureAlgorithm.ES256)
    expect(coseKey.x).toBeDefined()
    expect(coseKey.y).toBeDefined()
    expect(coseKey.d).toBeDefined()
  })

  test('create jwk from cose key', () => {
    const jwk = {
      kty: 'EC',
      d: 'hGc90b8KMIjIpZos81yEFbOMc0Ww3k5ZNWICzDwtFV4',
      use: 'sig',
      crv: 'P-256',
      x: 'eBUFGSPkdYwJ9TqYpcNxhAyr-A8wlWzrLQJppSi3x0E',
      y: 'Jnf8v4steg6Gr4IEFpg_xcM5xdHKdngbQN9ERJbJvl8',
      alg: 'ES256',
    }

    const newJwk = CoseKey.fromJwk(jwk).jwk

    expect(newJwk.kty).toStrictEqual(jwk.kty)
    expect(newJwk.d).toStrictEqual(jwk.d)
    expect(newJwk.crv).toStrictEqual(jwk.crv)
    expect(newJwk.x).toStrictEqual(jwk.x)
    expect(newJwk.y).toStrictEqual(jwk.y)
    expect(newJwk.alg).toStrictEqual(jwk.alg)
  })
})
