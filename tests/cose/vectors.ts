export const sign1TestVector01 = {
  uuid: 'D55A49BD-53D9-42B1-9E76-E0CF2AD33E9D',
  title: 'Sign1 w/ external input - ECDSA w/ SHA-256 (sign)',
  description: 'Sign with one signer using ECDSA w/ SHA-256 supplying external input',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
    y: 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
    d: 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
  },
  alg: 'ES256',
  'sign1::sign': {
    payload: '546869732069732074686520636f6e74656e742e',
    protectedHeaders: {
      cborHex: 'a10126',
      cborDiag: '{1: -7}',
    },
    unprotectedHeaders: {
      cborHex: 'a104423131',
      cborDiag: "{4: '11'}",
    },
    tbsHex: {
      cborHex: '846a5369676e61747572653143a101264c11aa22bb33cc44dd5500669954546869732069732074686520636f6e74656e742e',
      cborDiag: "[\"Signature1\", h'A10126', h'11AA22BB33CC44DD55006699', h'546869732069732074686520636F6E74656E742E']",
    },
    external: '11aa22bb33cc44dd55006699',
    detached: false,
    expectedOutput: {
      cborHex:
        'd28443a10126a10442313154546869732069732074686520636f6e74656e742e58403a7487d9a528cb61dd8e99bd652c12577fc47d70ee5af2e703c420584f060fc7a8d61e4a35862b2b531a8447030ab966aeed8dd45ebc507c761431e349995770',
      cborDiag:
        "18([h'A10126', {4: '11'}, h'546869732069732074686520636F6E74656E742E', h'3A7487D9A528CB61DD8E99BD652C12577FC47D70EE5AF2E703C420584F060FC7A8D61E4A35862B2B531A8447030AB966AEED8DD45EBC507C761431E349995770'])",
    },
    fixedOutputLength: 32,
  },
}

export const sign1TestVector02 = {
  uuid: '0F78DB1C-C30F-47B1-AF19-6D0C0B2F3803',
  title: 'Sign1 - ECDSA w/ SHA-256 (sign)',
  description: 'Sign with one signer using ECDSA w/ SHA-256',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
    y: 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4',
    d: 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM',
  },
  alg: 'ES256',
  'sign1::sign': {
    payload: '546869732069732074686520636f6e74656e742e',
    protectedHeaders: {
      cborHex: 'a201260300',
      cborDiag: '{1: -7, 3: 0}',
    },
    unprotectedHeaders: {
      cborHex: 'a104423131',
      cborDiag: "{4: '11'}",
    },
    tbsHex: {
      cborHex: '846a5369676e61747572653145a2012603004054546869732069732074686520636f6e74656e742e',
      cborDiag: "[\"Signature1\", h'A201260300', h'', h'546869732069732074686520636F6E74656E742E']",
    },
    external: '',
    detached: false,
    expectedOutput: {
      cborHex:
        'd28445a201260300a10442313154546869732069732074686520636f6e74656e742e58402ad3b9dcc1e13d04f357e11cc8acd825196620e62f0d8deca72672508b829d90e07a3f23be6aa36fd6ebd31e2ed08d1760bffd981f991bfc94a45199a54875c4',
      cborDiag:
        "18([h'A201260300', {4: '11'}, h'546869732069732074686520636F6E74656E742E', h'2AD3B9DCC1E13D04F357E11CC8ACD825196620E62F0D8DECA72672508B829D90E07A3F23BE6AA36FD6EBD31E2ED08D1760BFFD981F991BFC94A45199A54875C4'])",
    },
    fixedOutputLength: 34,
  },
}
