import { describe, expect, test } from 'vitest'
import { CWTStatusToken, CoseKey, StatusArray } from '../../src'
import { ISSUER_PRIVATE_KEY_JWK } from '../issuing/config'

describe('status-array', () => {
  test('should create and verify a CWTStatusToken with a StatusArray', async () => {
    const statusArray = new StatusArray(2)

    statusArray.set(0, 2)
    statusArray.set(1, 3)
    expect(statusArray.get(0)).toBe(2)
    expect(statusArray.get(1)).toBe(3)

    const cwtStatusToken = await CWTStatusToken.build({
      claimsSet: { statusArray },
      type: 'sign1',
      key: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    })
    const verify = await CWTStatusToken.verifyStatus({
      type: 'sign1',
      token: cwtStatusToken,
      key: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      index: 0,
      expectedStatus: 2,
    })

    expect(verify).toBeTruthy()
  })
})
