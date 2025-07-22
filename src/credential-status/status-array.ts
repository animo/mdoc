import * as zlib from 'pako'

const arraySize = 1024
export const allowedBitsPerEntry = [1, 2, 4, 8] as const
export type AllowedBitsPerEntry = (typeof allowedBitsPerEntry)[number]

export class StatusArray {
  private readonly _bitsPerEntry: AllowedBitsPerEntry
  private readonly statusBitMask: number
  private readonly data: Uint8Array

  constructor(bitsPerEntry: AllowedBitsPerEntry, byteArr?: Uint8Array) {
    if (!allowedBitsPerEntry.includes(bitsPerEntry)) {
      throw new Error(`Only bits ${allowedBitsPerEntry.join(', ')} per entry are allowed.`)
    }

    this._bitsPerEntry = bitsPerEntry
    this.statusBitMask = (1 << bitsPerEntry) - 1
    this.data = byteArr ? byteArr : new Uint8Array(arraySize)
  }

  private computeByteAndOffset(index: number): { byteIndex: number; bitOffset: number } {
    const byteIndex = Math.floor((index * this._bitsPerEntry) / 8)
    const bitOffset = (index * this._bitsPerEntry) % 8

    return { byteIndex, bitOffset }
  }

  get bitsPerEntry(): AllowedBitsPerEntry {
    return this._bitsPerEntry
  }

  set(index: number, status: number): void {
    if (status < 0 || status > this.statusBitMask) {
      throw new Error(`Invalid status: ${status}. Must be between 0 and ${this.statusBitMask}.`)
    }

    const { byteIndex, bitOffset } = this.computeByteAndOffset(index)

    // Clear current bits
    this.data[byteIndex] &= ~(this.statusBitMask << bitOffset)

    // Set new status bits
    this.data[byteIndex] |= (status & this.statusBitMask) << bitOffset
  }

  get(index: number): number {
    const { byteIndex, bitOffset } = this.computeByteAndOffset(index)

    return (this.data[byteIndex] >> bitOffset) & this.statusBitMask
  }

  compress(): Uint8Array {
    return zlib.deflate(this.data)
  }
}
