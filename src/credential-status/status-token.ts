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

enum CwtProtectedHeaders {
    TYPE = 16
}
enum CwtStatusListClaims {
    StatusListUri = 2,
    IssuedAt = 6,
    StatusList = 65533
}

export class CWTStatusToken {
    static async build(options: CWTStatusTokenOptions): Promise<Uint8Array> {
        const cwt = new CWT()
        cwt.setHeaders({
            protected: {
                [CwtProtectedHeaders.TYPE]: 'application/statuslist+cwt',
            }
        });
        cwt.setClaims({
            [CwtStatusListClaims.StatusListUri]: 'https://example.com/statuslist', // Where the status list is going to be hosted
            [CwtStatusListClaims.IssuedAt]: Math.floor(Date.now() / 1000),
            [CwtStatusListClaims.StatusList]: StatusList.buildCborStatusList({ statusArray: options.statusArray, aggregationUri: options.aggregationUri }),
        });
        return cborEncode(await cwt.create({ type: options.type, key: options.key }))
    }
}