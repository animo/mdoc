import { StatusArray } from "./status-array";
import { StatusList } from "./status-list";
import { cborEncode } from "../cbor";
import { CoseKey } from "../cose";
import { CWT } from "../cwt";

export class CWTStatusToken {
    static async build(statusArray: StatusArray, type: 'sign1' | 'mac0' = 'sign1', key: CoseKey, aggregationUri?: string): Promise<Uint8Array> {
        const cwt = new CWT()
        cwt.setHeaders({
            protected: {
                type: 'application/statuslist+cwt',
            }
        });
        cwt.setClaims({
            2: 'https://example.com/statuslist', // Where the status list is going to be hosted
            6: Math.floor(Date.now() / 1000),
            65533: StatusList.buildCborStatusList(statusArray, aggregationUri),
        });
        return cborEncode(await cwt.create({ type, key }))
    }
}