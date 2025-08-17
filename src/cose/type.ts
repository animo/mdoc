export enum CoseStructureType {
  Sign = 'sign',
  Sign1 = 'sign1',
  Encrypt = 'encrypt',
  Encrypt0 = 'encrypt0',
  Mac = 'mac',
  Mac0 = 'mac0',
}
export enum CoseStructureTag {
  Sign = 98,
  Sign1 = 18,
  Encrypt = 96,
  Encrypt0 = 16,
  Mac = 97,
  Mac0 = 17,
}
export const CoseTypeToTag: Record<CoseStructureType, CoseStructureTag> = {
  [CoseStructureType.Sign]: CoseStructureTag.Sign,
  [CoseStructureType.Sign1]: CoseStructureTag.Sign1,
  [CoseStructureType.Encrypt]: CoseStructureTag.Encrypt,
  [CoseStructureType.Encrypt0]: CoseStructureTag.Encrypt0,
  [CoseStructureType.Mac]: CoseStructureTag.Mac,
  [CoseStructureType.Mac0]: CoseStructureTag.Mac0,
}
