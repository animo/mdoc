import { describe, expect, test } from 'vitest'
import { CoseKey, CwtStatusToken, StatusArray } from '../../src'
import { CoseStructureType } from '../../src/cose'
import { mdocContext } from '../context'
import { ISSUER_PRIVATE_KEY_JWK } from '../issuing/config'

describe('CWTStatusToken', () => {
  test('should create and verify a CWTStatusToken with a StatusArray', async () => {
    const statusArray = new StatusArray(2)

    statusArray.set(0, 2)
    statusArray.set(1, 3)
    expect(statusArray.get(0)).toBe(2)
    expect(statusArray.get(1)).toBe(3)

    const cwtStatusToken = await CwtStatusToken.sign({
      mdocContext,
      statusListUri: 'https://example.com/status-list',
      claimsSet: { statusArray },
      type: CoseStructureType.Sign1,
      key: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
    })
    const verify = await CwtStatusToken.verifyStatus({
      mdocContext,
      token: cwtStatusToken,
      key: CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK),
      index: 0,
      expectedStatus: 2,
    })

    expect(verify).toBeTruthy()
  })
})
