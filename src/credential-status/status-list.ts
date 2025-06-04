import { StatusArray } from "./status-array";
import { cborEncode } from "../cbor";

interface CborStatusListOptions {
    statusArray: StatusArray;
    aggregationUri?: string;
}

export class StatusList {
    static buildCborStatusList(options: CborStatusListOptions): Uint8Array {
        const compressed = options.statusArray.compress();

        const statusList: Record<string, any> = {
            bits: options.statusArray.getBitsPerEntry(),
            lst: compressed,
        };

        if (options.aggregationUri) {
            statusList.aggregation_uri = options.aggregationUri;
        }
        return cborEncode(statusList);
    }
}