import { describe, expect, test } from 'vitest'
import { CoseKey, CWTStatusToken, StatusArray } from '../../src'
import { ISSUER_PRIVATE_KEY_JWK } from '../issuing/config';

describe('status-array', () => {
    test('should create a status array and set/get values', async () => {
        const statusArray = new StatusArray(2, 10);

        statusArray.set(0, 2);
        statusArray.set(1, 3);
        expect(statusArray.get(0)).toBe(2);
        expect(statusArray.get(1)).toBe(3);

        // Will remove it before merging
        console.log(await CWTStatusToken.build(statusArray, 'sign1', CoseKey.fromJwk(ISSUER_PRIVATE_KEY_JWK)));
    })
})
