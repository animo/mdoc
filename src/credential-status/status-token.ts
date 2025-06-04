import { StatusArray } from "./status-array";
import { StatusList } from "./status-list";
import { cborEncode } from "../cbor";
import { CoseKey } from "../cose";
import { CWT } from "../cwt";

interface CWTStatusTokenOptions {
    statusArray: StatusArray;
    aggregationUri?: string;
    type: 'sign1' | 'mac0';
    key: CoseKey;
}

enum CWTProtectedHeaders {
    TYPE = 16
}
enum CWTClaims {
    STATUS_LIST_URI = 2,
    ISSUED_AT = 6,
    STATUS_LIST = 65533
}

export class CWTStatusToken {
    static async build(options: CWTStatusTokenOptions): Promise<Uint8Array> {
        const cwt = new CWT()
        cwt.setHeaders({
            protected: {
                [CWTProtectedHeaders.TYPE]: 'application/statuslist+cwt',
            }
        });
        cwt.setClaims({
            [CWTClaims.STATUS_LIST_URI]: 'https://example.com/statuslist', // Where the status list is going to be hosted
            [CWTClaims.ISSUED_AT]: Math.floor(Date.now() / 1000),
            [CWTClaims.STATUS_LIST]: StatusList.buildCborStatusList({ statusArray: options.statusArray, aggregationUri: options.aggregationUri }),
        });
        return cborEncode(await cwt.create({ type: options.type, key: options.key }))
    }
}