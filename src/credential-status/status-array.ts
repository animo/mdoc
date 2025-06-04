import * as zlib from "zlib";

const allowedBitsPerEntry = [1, 2, 4, 8] as const
type AllowedBitsPerEntry = typeof allowedBitsPerEntry[number]

export class StatusArray {
    private readonly bitsPerEntry: 1 | 2 | 4 | 8;
    private readonly statusBitMask: number;
    private readonly data: Uint8Array;

    constructor(bitsPerEntry: AllowedBitsPerEntry, totalEntries: number) {
        if (!allowedBitsPerEntry.includes(bitsPerEntry)) {
            throw new Error("Only 1, 2, 4, or 8 bits per entry are allowed.");
        }

        this.bitsPerEntry = bitsPerEntry;
        this.statusBitMask = (1 << bitsPerEntry) - 1;

        const totalBits = totalEntries * bitsPerEntry;
        const byteSize = Math.ceil(totalBits / 8);
        this.data = new Uint8Array(byteSize);
    }

    private computeByteAndOffset(index: number): [number, number] {
        const byteIndex = Math.floor((index * this.bitsPerEntry) / 8);
        const bitOffset = (index * this.bitsPerEntry) % 8;

        return [byteIndex, bitOffset];
    }

    getBitsPerEntry(): 1 | 2 | 4 | 8 {
        return this.bitsPerEntry;
    }

    set(index: number, status: number): void {
        if (status < 0 || status > this.statusBitMask) {
            throw new Error(`Invalid status: ${status}. Must be between 0 and ${this.statusBitMask}.`);
        }

        const [byteIndex, bitOffset] = this.computeByteAndOffset(index);

        // Clear current bits
        this.data[byteIndex] &= ~(this.statusBitMask << bitOffset);

        // Set new status bits
        this.data[byteIndex] |= (status & this.statusBitMask) << bitOffset;
    }

    get(index: number): number {
        const [byteIndex, bitOffset] = this.computeByteAndOffset(index);

        return (this.data[byteIndex] >> bitOffset) & this.statusBitMask;
    }

    compress(): Uint8Array {
        return zlib.deflateSync(this.data, { level: zlib.constants.Z_BEST_COMPRESSION });
    }
}