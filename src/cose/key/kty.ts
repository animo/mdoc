export enum KeyType {
  Okp = 1,
  Ec = 2,
  Oct = 4,
  Reserved = 0,
}

export enum JwkKeyType {
  Okp = KeyType.Okp,
  Ec = KeyType.Ec,
  Oct = KeyType.Oct,
}
