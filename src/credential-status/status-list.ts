import { StatusArray } from "./status-array";
import { cborEncode } from "../cbor";

export class StatusList {
    static buildCborStatusList(statusArray: StatusArray, aggregationUri?: string): Uint8Array {
        const compressed = statusArray.compress();

        const statusList: Record<string, any> = {
            bits: statusArray.getBitsPerEntry(),
            lst: compressed,
        };

        if (aggregationUri) {
            statusList.aggregation_uri = aggregationUri;
        }
        return cborEncode(statusList);
    }
}