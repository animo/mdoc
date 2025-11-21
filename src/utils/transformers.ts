const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const bytesToBase64 = (bytes: Uint8Array): string => {
  let result = ''
  let i: number

  for (i = 0; i < bytes.length - 2; i += 3) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    result += BASE64_CHARS[(chunk >> 18) & 63]
    result += BASE64_CHARS[(chunk >> 12) & 63]
    result += BASE64_CHARS[(chunk >> 6) & 63]
    result += BASE64_CHARS[chunk & 63]
  }

  // Handle padding
  if (i < bytes.length) {
    const chunk = (bytes[i] << 16) | (i + 1 < bytes.length ? bytes[i + 1] << 8 : 0)
    result += BASE64_CHARS[(chunk >> 18) & 63]
    result += BASE64_CHARS[(chunk >> 12) & 63]
    result += i + 1 < bytes.length ? BASE64_CHARS[(chunk >> 6) & 63] : '='
    result += '='
  }

  return result
}

const base64ToBytes = (base64: string): Uint8Array => {
  // Validate input - only base64 characters and padding are allowed
  const validBase64Regex = /^[A-Za-z0-9+/]*={0,2}$/
  if (!validBase64Regex.test(base64)) {
    throw new Error('Invalid base64 string: contains invalid characters')
  }

  // Remove padding
  const cleanBase64 = base64.replace(/=/g, '')
  const length = cleanBase64.length
  const bytes = new Uint8Array((length * 3) >> 2)

  let byteIndex = 0
  for (let i = 0; i < length; i += 4) {
    const a = BASE64_CHARS.indexOf(cleanBase64[i])
    const b = BASE64_CHARS.indexOf(cleanBase64[i + 1])
    const c = i + 2 < length ? BASE64_CHARS.indexOf(cleanBase64[i + 2]) : 0
    const d = i + 3 < length ? BASE64_CHARS.indexOf(cleanBase64[i + 3]) : 0

    bytes[byteIndex++] = (a << 2) | (b >> 4)
    if (i + 2 < length) bytes[byteIndex++] = ((b & 15) << 4) | (c >> 2)
    if (i + 3 < length) bytes[byteIndex++] = ((c & 3) << 6) | d
  }

  return bytes
}

const bytesToBase64Url = (bytes: Uint8Array): string => {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

const base64UrlToBytes = (base64url: string): Uint8Array => {
  // Validate input - only base64url characters (no padding) are allowed
  const validBase64UrlRegex = /^[A-Za-z0-9_-]*$/
  if (!validBase64UrlRegex.test(base64url)) {
    throw new Error('Invalid base64url string: contains invalid characters')
  }

  // Convert base64url to base64
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '='
  }
  return base64ToBytes(base64)
}

const bytesToHex = (bytes: Uint8Array): string => {
  let result = ''
  for (let i = 0; i < bytes.length; i++) {
    const hex = bytes[i].toString(16)
    result += hex.length === 1 ? `0${hex}` : hex
  }
  return result
}

const hexToBytes = (hex: string): Uint8Array => {
  // Validate input - only hex characters are allowed, and length must be even
  const validHexRegex = /^[0-9a-fA-F]*$/
  if (!validHexRegex.test(hex)) {
    throw new Error('Invalid hex string: contains invalid characters')
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: length must be even')
  }

  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

export const base64 = {
  decode: base64ToBytes,
  encode: bytesToBase64,
}

export const base64url = {
  decode: base64UrlToBytes,
  encode: bytesToBase64Url,
}

export const hex = {
  decode: hexToBytes,
  encode: bytesToHex,
}

export const bytesToString = (bytes: Uint8Array): string => {
  let result = ''
  let i = 0

  while (i < bytes.length) {
    const byte1 = bytes[i++]

    if (byte1 < 0x80) {
      // Single byte character
      result += String.fromCharCode(byte1)
    } else if (byte1 < 0xe0) {
      // Two byte character
      const byte2 = bytes[i++]
      result += String.fromCharCode(((byte1 & 0x1f) << 6) | (byte2 & 0x3f))
    } else if (byte1 < 0xf0) {
      // Three byte character
      const byte2 = bytes[i++]
      const byte3 = bytes[i++]
      result += String.fromCharCode(((byte1 & 0x0f) << 12) | ((byte2 & 0x3f) << 6) | (byte3 & 0x3f))
    } else {
      // Four byte character - convert to surrogate pair
      const byte2 = bytes[i++]
      const byte3 = bytes[i++]
      const byte4 = bytes[i++]
      const codePoint = ((byte1 & 0x07) << 18) | ((byte2 & 0x3f) << 12) | ((byte3 & 0x3f) << 6) | (byte4 & 0x3f)
      const surrogate1 = 0xd800 + ((codePoint - 0x10000) >> 10)
      const surrogate2 = 0xdc00 + ((codePoint - 0x10000) & 0x3ff)
      result += String.fromCharCode(surrogate1, surrogate2)
    }
  }
  return result
}

export const stringToBytes = (str: string): Uint8Array => {
  const bytes: number[] = []

  for (let i = 0; i < str.length; i++) {
    let codePoint = str.charCodeAt(i)

    // Handle surrogate pairs
    if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < str.length) {
      const low = str.charCodeAt(i + 1)
      if (low >= 0xdc00 && low <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00)
        i++
      }
    }

    if (codePoint < 0x80) {
      // Single byte
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      // Two bytes
      bytes.push(0xc0 | (codePoint >> 6))
      bytes.push(0x80 | (codePoint & 0x3f))
    } else if (codePoint < 0x10000) {
      // Three bytes
      bytes.push(0xe0 | (codePoint >> 12))
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f))
      bytes.push(0x80 | (codePoint & 0x3f))
    } else {
      // Four bytes
      bytes.push(0xf0 | (codePoint >> 18))
      bytes.push(0x80 | ((codePoint >> 12) & 0x3f))
      bytes.push(0x80 | ((codePoint >> 6) & 0x3f))
      bytes.push(0x80 | (codePoint & 0x3f))
    }
  }

  return new Uint8Array(bytes)
}

export const concatBytes = (byteArrays: Array<Uint8Array>): Uint8Array => {
  const totalLength = byteArrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of byteArrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

export const compareBytes = (lhs: Uint8Array, rhs: Uint8Array) => {
  if (lhs === rhs) return true
  if (lhs.byteLength !== rhs.byteLength) return false
  return lhs.every((b, i) => b === rhs[i])
}
