export enum CoseType {
  Sign = 'sign',
  Sign1 = 'sign1',
  Encrypt = 'encrypt',
  Encrypt0 = 'encrypt0',
  Mac = 'mac',
  Mac0 = 'mac0',
}
export enum CoseTag {
  Sign = 98,
  Sign1 = 18,
  Encrypt = 96,
  Encrypt0 = 16,
  Mac = 97,
  Mac0 = 17,
}
export const CoseTypeToTag: Record<CoseType, CoseTag> = {
  [CoseType.Sign]: CoseTag.Sign,
  [CoseType.Sign1]: CoseTag.Sign1,
  [CoseType.Encrypt]: CoseTag.Encrypt,
  [CoseType.Encrypt0]: CoseTag.Encrypt0,
  [CoseType.Mac]: CoseTag.Mac,
  [CoseType.Mac0]: CoseTag.Mac0,
}
