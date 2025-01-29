<p align="center">
  <picture>
   <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-light-no-text_ok9auy.svg">
   <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-dark-no-text_fqqdq9.svg">
   <img alt="Animo Logo" height="250px" />
  </picture>
</p>

<h1 align="center" ><b>mDOC and mDL - TypeScript</b></h1>

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver’s Licenses): an ISO standard for digital driver licenses.

This is a JavaScript library for Node.JS, browers and React Native to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with **ISO 18013-7 (draft's date: 2024-03-12)**.

<h4 align="center">Powered by &nbsp; 
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-light-text_cma2yo.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-dark-text_uccvqa.svg">
    <img alt="Animo Logo" height="12px" />
  </picture>
</h4><br>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> 
  &nbsp;|&nbsp;
  <a href="#usage">Usage</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
  &nbsp;|&nbsp;
  <a href="#credits">Credits</a>
</p>

## Installation

```bash
npm i @animo-id/mdoc
```

## Usage

### Verifying a credential

```javascript
import { Verifier } from "@animo-id/mdoc";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, "hex");
  const encodedSessionTranscript = Buffer.from(
    encodedSessionTranscriptHex,
    "hex"
  );
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, "hex");

  const trustedCerts = [fs.readFileSync("./caCert1.pem") /*, ... */];
  const verifier = new Verifier(trustedCerts);
  const mdoc = await verifier.verify(encodedDeviceResponse, {
    ephemeralReaderKey,
    encodedSessionTranscript,
  });

  //at this point the issuer and device signature are valids.
  inspect(mdoc);
})();
```

### Getting diagnostic information

```javascript
import { Verifier } from "@animo-id/mdoc";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, "hex");
  const encodedSessionTranscript = Buffer.from(
    encodedSessionTranscriptHex,
    "hex"
  );
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, "hex");

  const trustedCerts = [fs.readFileSync("./caCert1.pem") /*, ... */];
  const verifier = new Verifier(trustedCerts);

  const diagnosticInfo = await verifier.getDiagnosticInformation(
    encodedDeviceResponse,
    {
      ephemeralReaderKey,
      encodedSessionTranscript,
    }
  );

  inspect(diagnosticInfo);
})();
```

##$ Issuing a credential

```js
import { MDoc, Document } from "@animo-id/mdoc";
import { inspect } from "node:util";

(async () => {
  const document = await new Document("org.iso.18013.5.1.mDL")
    .addIssuerNameSpace("org.iso.18013.5.1", {
      family_name: "Jones",
      given_name: "Ava",
      birth_date: "2007-03-25",
    })
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo({
      signed: new Date(),
    })
    .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
    .sign({
      issuerPrivateKey,
      issuerCertificate,
    });

  const mdoc = new MDoc([document]).encode();

  inspect(encoded);
})();
```

##$ Generating a device response

```js
import { DeviceResponse, MDoc } from "@animo-id/mdoc";

(async () => {
  let issuerMDoc;
  let deviceResponseMDoc;

  /**
   * This is what the MDL issuer does to generate a credential:
   */
  {
    let issuerPrivateKey;
    let issuerCertificate;
    let devicePublicKey; // the public key for the device, as a JWK

    const document = await new Document("org.iso.18013.5.1.mDL")
      .addIssuerNameSpace("org.iso.18013.5.1", {
        family_name: "Jones",
        given_name: "Ava",
        birth_date: "2007-03-25",
      })
      .useDigestAlgorithm("SHA-256")
      .addValidityInfo({
        signed: new Date(),
      })
      .addDeviceKeyInfo({ deviceKey: devicePublicKey })
      .sign({
        issuerPrivateKey,
        issuerCertificate,
        alg: "ES256",
      });

    issuerMDoc = new MDoc([document]).encode();
  }

  /**
   * This is what the DEVICE does to generate a response...
   */
  {
    let devicePrivateKey; // the private key for the device, as a JWK

    // Parameters coming from the OID4VP transaction
    let mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce;
    let presentationDefinition = {
      id: "family_name_only",
      input_descriptors: [
        {
          id: "org.iso.18013.5.1.mDL",
          format: { mso_mdoc: { alg: ["EdDSA", "ES256"] } },
          constraints: {
            limit_disclosure: "required",
            fields: [
              {
                path: ["$['org.iso.18013.5.1']['family_name']"],
                intent_to_retain: false,
              },
            ],
          },
        },
      ],
    };

    deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
      .usingPresentationDefinition(presentationDefinition)
      .usingSessionTranscriptForOID4VP(
        mdocGeneratedNonce,
        clientId,
        responseUri,
        verifierGeneratedNonce
      )
      .authenticateWithSignature(devicePrivateKey, "ES256")
      .sign();
  }
})();
```

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this repository is based.
- [auer-martin](https://github.com/auer-martin) for removing node.js dependencies and providing a pluggable crypto interface
