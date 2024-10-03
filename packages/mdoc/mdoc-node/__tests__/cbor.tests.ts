import { hex } from 'buffer-tag';

import {
  areEqual,
  cborDecode,
  cborDecodeUnknown,
  cborEncode,
  DataItem,
} from '@protokoll/mdoc-client';

describe('cbor', () => {
  it('should properly decode a nested map', () => {
    const encoded = hex`d81855b9000163666f6fd8184bb90001636261726362617a`;
    const decoded = cborDecode(encoded) as DataItem<
      Map<string, DataItem<Map<string, string>>>
    >;
    expect(decoded).toBeInstanceOf(DataItem);
    expect(decoded.data.get('foo')).toBeInstanceOf(DataItem);
    expect(decoded.data.get('foo')?.data.get('bar')).toBe('baz');
  });

  it('should properly encoded and decoded maps', () => {
    const encoded = cborEncode(DataItem.fromData({ foo: 'baz' }));
    const decoded = cborDecodeUnknown(encoded);
    const reEncode = cborEncode(decoded);
    expect(areEqual(reEncode, encoded)).toBeTruthy();
  });

  it('should properly encoded and decoded with arrays', () => {
    const encoded = cborEncode(
      DataItem.fromData({ foo: DataItem.fromData([1, 2, 3, 4, 5]) })
    );
    const decoded = cborDecode(encoded) as DataItem<
      Map<string, DataItem<number[]>>
    >;
    expect(decoded.data.get('foo')?.data).toStrictEqual([1, 2, 3, 4, 5]);
    const reEncode = cborEncode(decoded);
    expect(areEqual(reEncode, encoded)).toBeTruthy();
  });

  it('should properly encoded and decoded with buffers', () => {
    const buffer = new Uint8Array(Buffer.from('abcdefghijk', 'utf-8'));
    const encoded = cborEncode(
      DataItem.fromData({ foo: DataItem.fromData(buffer) })
    );
    const decoded = cborDecode(encoded) as DataItem<
      Map<string, DataItem<Uint8Array>>
    >;
    expect(decoded.data.get('foo')?.data).toBeInstanceOf(Uint8Array);
    const reEncode = cborEncode(decoded);
    expect(areEqual(reEncode, encoded)).toBeTruthy();
  });

  it('should be able to encode/decode a DataItem', () => {
    const encoded = hex`d8185863a4686469676573744944006672616e646f6d58208798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65`;
    const decoded = cborDecode(encoded) as DataItem;
    expect(decoded).toBeInstanceOf(DataItem);
    expect(Buffer.from(decoded.buffer).toString('hex')).toBe(
      Buffer.from(DataItem.fromData(decoded.data).buffer).toString('hex')
    );
    const reEncode = cborEncode(DataItem.fromData(decoded.data));
    expect(areEqual(reEncode, encoded)).toBeTruthy();
  });
});
