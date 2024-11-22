import fs from 'node:fs'
import { hex } from 'buffer-tag'

import { X509Certificate } from '@peculiar/x509'
import { describe, expect, it } from 'vitest'
import { mdocContext } from '..'
import { Verifier, defaultCallback } from '../..'
export const ISSUER_CERTIFICATE = fs.readFileSync(`${__dirname}/issuer.pem`, 'utf-8')

describe('example 3: device response with partial and tampered disclosure', () => {
  const ephemeralReaderKey = hex`534b526561646572`
  const encodedSessionTranscript = hex`d818589e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667`
  const encodedDeviceResponse = hex`b900036776657273696f6e63312e3069646f63756d656e747381b9000367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564b900026a6e616d65537061636573b90001716f72672e69736f2e31383031332e352e3186d8185868a4686469676573744944006672616e646f6d5820b71c5cac1e15923cfad7468c061da8600dd3bc32015a54c7c2b1953fb9e8452771656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c75656857696c6c69616d73d8185865b90004686469676573744944016672616e646f6d58205e01b2280be9c0ac4658bd34983bcfbf8c95cbeac19a5e3338fb6b476093315a71656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c7565644a6f686ed818586eb90004686469676573744944026672616e646f6d5820de5abc9d35863a82245f0477720c8253e37d0f8ef425956cf37cca33a83984f571656c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c7565d903ec6a313938302d30362d3135d8185868b90004686469676573744944056672616e646f6d58205a9cd291a808ae1dac3d0807a3031cafe8e2b374050388bc932864a95f82e26e71656c656d656e744964656e7469666965726f69737375696e675f636f756e7472796c656c656d656e7456616c7565625553d818586eb90004686469676573744944066672616e646f6d5820f849a4010a2e109142451e56c4bf0dd4c4e40249e0f719fb6e2a45e68412a31a71656c656d656e744964656e7469666965727169737375696e675f617574686f726974796c656c656d656e7456616c7565664e5920444d56d8185873b90004686469676573744944076672616e646f6d5820171ca61cdc1de90abf7eb74f1e4b5b4a261b0cc3d5938ac23be8b361c69d249171656c656d656e744964656e7469666965727469737375696e675f6a7572697364696374696f6e6c656c656d656e7456616c7565684e657720596f726b6a697373756572417574688443a10126a20442313118218159022e3082022a308201d0a003020102021457c6ccd308bde43eca3744f2a87138dabbb884e8300a06082a8648ce3d0403023053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d56301e170d3233303931343134353531385a170d3333303931313134353531385a3053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d563059301306072a8648ce3d020106082a8648ce3d03010703420004893c2d8347906dc6cd69b7f636af4bfd533f96184f0aadacd10830da4471dbdb60ac170d1cfc534fae2d9dcd488f7747fdf978d925ea31e9e9083c382ba9ed53a38181307f301d0603551d0e04160414ab6d2e03b91d492240338fbccadefd9333eaf6c7301f0603551d23041830168014ab6d2e03b91d492240338fbccadefd9333eaf6c7300f0603551d130101ff040530030101ff302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465300a06082a8648ce3d0403020348003045022009fd0cab97b03e78f64e74d7dcee88668c476a0afc5aa2cebffe07d3be772ea9022100da38abc98a080f49f24ffece1fffc8a6cdd5b2c0b5da8fc7b767ac3a95dcb83e590319d818590314b900066776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473b900026f6f72672e637573746f6d2e74657374a10058201d8aeee64815a0fd40f751fba54baecbd34f02a16f1ec47dc991e2f791ca44a5716f72672e69736f2e31383031332e352e31ac00582056da6532090783336cdd615da2b4e2ba52098c9935ea77e9e700be27e4b65b32015820842183a9529c7aedca84822642628de8b3a715c4ba74ca7dd9a3e3c7da1b94f5025820712765f58ad88f21e0b6018711d533175af08825d6d7c74fac876a08985ecf20035820eaa71a09aaca7858437c4b7f49ab6c4aa2a6b6f186a8a71d4c4144c14111bc40045820eea2cad34743e16df9658a88eaae5a53237bb625e35f2af5f7eb0e346f034c07055820c32639110c08a2549737b26f9e50aaa698a88f36d53f5a1f33b152d7a41b1ef7065820d8f724284e7d33400c44192f00706ed0b6d60b721e6055fe18c9845a6e3eb42a07582050863328a3ed9e1141c82ee8b830c6e553a9d9e78b681975ee3e2225e203de2a08582035e369c38c314c352cf9ba23a1b2ca37fb5e7d9dea20c03de73356f77ff0685509582031ddd32867e9515d3f7b2ad78bf8bef8296a85d2f4cf9986804a6b0bd763988f0a582043d470465c7fb28e0f4af57ad11d55729cd4e11bcd488ec998dfc8ff99fc12e00b58200aa24b81a8927e94d69cc84ec7382fd5371b8970a41de561ab8b9a6eb51c4c706d6465766963654b6579496e666fb90001696465766963654b6579a40102215820881879ca7a238b19bf0f4c1f8c00e9a2e19ba7a6f73eae92b851d4de1b508559225820a314b538039127b5cd50735f54519e33c134450545c5603ad9f263facc56d377200167646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fb90003667369676e6564c074323032332d30392d32395431353a35373a31325a6976616c696446726f6dc074323032332d30392d32395431353a35373a31325a6a76616c6964556e74696cc074323037332d30392d32395431353a35373a31325a5840bcc0aa350715291e4b6fbd609523eed20d6cad54ddb13e57e4e4ce409197b9585aceb7a787c5d2d8d7726aef2907509be35238d496518f96bdb15fb8615ddebd6c6465766963655369676e6564b900026a6e616d65537061636573d81841a06a64657669636541757468b900016f6465766963655369676e61747572658443a10126a10442313158d2d81858ce847444657669636541757468656e7469636174696f6e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667756f72672e69736f2e31383031332e352e312e6d444cd81841a05840105baf1c0e5c3704dac8f662bdf54ae76d8e51c021d6433f42b60637888f89a5b7c67f1ab56b62d347878f4de88786a92f256640f7709ff6d4bead043378a5476673746174757300`
  const verifier = new Verifier()

  it('should verify properly', async () => {
    await expect(
      verifier.verifyDeviceResponse(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
          encodedDeviceResponse,
          ephemeralReaderKey,
          encodedSessionTranscript,
        },
        mdocContext
      )
    ).rejects.toThrow(
      'The calculated digest for org.iso.18013.5.1/family_name attribute must match the digest in the issuerAuth element'
    )
  })

  it('should return the decoded response when skipping the error', async () => {
    const { documents } = await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        encodedDeviceResponse,
        ephemeralReaderKey,
        encodedSessionTranscript,
        onCheck: (v) => {
          if (v.category === 'DATA_INTEGRITY') {
            return
          }
          defaultCallback(v)
        },
      },
      mdocContext
    )
    const issuerAuth = documents[0]?.issuerSigned.issuerAuth
    if (!issuerAuth) throw new Error('IssuerAuth not found')

    const ns = 'org.iso.18013.5.1'
    expect(
      await documents[0]?.issuerSigned.nameSpaces
        .get(ns)
        ?.find((f) => f.elementIdentifier === 'family_name')
        ?.isValid(ns, issuerAuth, mdocContext)
    ).toBe(false)
  })

  it('should return the invalid attribute in the diagnostic info', async () => {
    const di = await verifier.getDiagnosticInformation(
      encodedDeviceResponse,
      {
        trustedCertificates: [new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData)],
        ephemeralReaderKey,
        encodedSessionTranscript,
      },
      mdocContext
    )
    expect(di.attributes.find((a) => a.id === 'family_name')?.isValid).toBe(false)
  })

  // it('should be able to verify without ephemeralReaderKey and encodedSessionTrasncript', async () => {
  //   await verifier.verify(deviceResponse, {
  //     onCheck: (verification, original) => {
  //       if (verification.category === 'DEVICE_AUTH') {
  //         return;
  //       }
  //       original(verification);
  //     },
  //   });
  // });

  // it('should contain only the disclosed fields', async () => {
  //   const { documents } = await verifier.verify(deviceResponse, {
  //     ephemeralReaderKey,
  //     encodedSessionTranscript,
  //   });

  //   const numberOfAttributes = documents[0]
  //     .issuerSigned
  //     .nameSpaces['org.iso.18013.5.1']
  //     .length;

  //   expect(numberOfAttributes).toBe(6);
  // });

  // it('should validate the digest of all fields', async () => {
  //   const { documents } = await verifier.verify(deviceResponse, {
  //     ephemeralReaderKey,
  //     encodedSessionTranscript,
  //   });

  //   const allFieldsAreValid = (await Promise.all(documents[0]
  //     .issuerSigned
  //     .nameSpaces['org.iso.18013.5.1']
  //     .map((field) => field.isValid()))).every(Boolean);

  //   expect(allFieldsAreValid).toBe(true);
  // });
})
