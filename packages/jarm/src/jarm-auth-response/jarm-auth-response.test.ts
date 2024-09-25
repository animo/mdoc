import * as jose from 'jose';
import assert from 'node:assert';
import { describe, it } from 'node:test';

import type { JWK } from '@protokoll/core';
import { NOT_IMPLEMENTED } from '@protokoll/core';

import { JarmError } from '../e-jarm.js';
import {
  ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK,
  ISO_MDL_7_JAR_AUTH_REQUEST_PARAMS,
  ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
  ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
} from './jarm-auth-response.fixtures.js';
import { validateJarmDirectPostJwtResponse } from './jarm-auth-response.js';

export const decrypt = async (input: {
  jwe: string;
  jwk: JWK;
  alg?: string;
}) => {
  const { jwe, jwk } = input;
  const decode = TextDecoder.prototype.decode.bind(new TextDecoder());
  const privateKey = await jose.importJWK(jwk);

  const { plaintext, protectedHeader } = await jose.compactDecrypt(
    jwe,
    privateKey
  );

  return {
    plaintext: decode(plaintext),
    protectedHeader,
  };
};

void describe('Jarm Auth Response', () => {
  void it(`'ISO_MDL_7_JARM_AUTH_RESPONSE' can be validated`, async () => {
    const { authRequestParams, authResponseParams } =
      await validateJarmDirectPostJwtResponse(
        { response: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT },
        {
          openid4vp: {
            authRequest: {
              getParams: () => ({
                authRequestParams: ISO_MDL_7_JAR_AUTH_REQUEST_PARAMS,
              }),
            },
          },
          jose: {
            jwe: { decrypt },
            jws: {
              verify: () =>
                NOT_IMPLEMENTED({
                  message: 'Verification Not needed',
                  error: JarmError,
                }),
            },
          },
          wallet: {
            getJwk: input => {
              if (
                input.kid === ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK.kid
              ) {
                return { jwk: ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK };
              } else {
                throw new Error('Received jwk with invalid kid.');
              }
            },
          },
        }
      );

    assert.deepEqual(
      ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
      authResponseParams
    );
    assert.deepEqual(authRequestParams, authRequestParams);
  });
});

//export const encrypt = async () => {
//const encode = TextEncoder.prototype.encode.bind(new TextEncoder());
//const recipientPublicKey = await jose.importJWK(
//ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
//'ECDH-ES'
//);

//const jwe = await new jose.CompactEncrypt(
//encode(JSON.stringify(ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS))
//)
//.setProtectedHeader(ISO_MDL_7_JARM_AUTHORIZATION_RESPONSE_JWT_HEADER)
//.setKeyManagementParameters({
//apu: encode(ISO_MDL_7_JARM_AUTHORIZATION_RESPONSE_JWT_HEADER.apu),
//apv: encode(ISO_MDL_7_JARM_AUTHORIZATION_RESPONSE_JWT_HEADER.apv),
//})
//.encrypt(recipientPublicKey);

//return jwe;
//};
