import { CborStructure } from '../../cbor'
import { MdlError } from '../errors'
import { DeviceMac, type DeviceMacStructure } from './device-mac'
import { DeviceSignature, type DeviceSignatureStructure } from './device-signature'

export type DeviceAuthStructure = {
  deviceSignature?: DeviceSignatureStructure
  deviceMac?: DeviceMacStructure
}

export type DeviceAuthOptions = {
  deviceSignature?: DeviceSignature
  deviceMac?: DeviceMac
}

export class DeviceAuth extends CborStructure {
  public deviceSignature?: DeviceSignature
  public deviceMac?: DeviceMac

  public constructor(options: DeviceAuthOptions) {
    super()

    this.deviceSignature = options.deviceSignature
    this.deviceMac = options.deviceMac

    this.assertEitherMacOrSignature()
  }

  private assertEitherMacOrSignature() {
    if (this.deviceMac && this.deviceSignature) {
      throw new MdlError('deviceAuth can only contain either a deviceMac or deviceSignature')
    }

    if (!this.deviceMac && !this.deviceSignature) {
      throw new MdlError('deviceAuth must contain either a deviceMac or deviceSignature')
    }
  }

  public encodedStructure(): DeviceAuthStructure {
    this.assertEitherMacOrSignature()

    if (this.deviceSignature) {
      return {
        deviceSignature: this.deviceSignature.encodedStructure(),
      }
    }

    if (this.deviceMac) {
      return {
        deviceMac: this.deviceMac.encodedStructure(),
      }
    }

    throw new MdlError('unreachable')
  }

  public static override fromEncodedStructure(
    encodedStructure: DeviceAuthStructure | Map<string, unknown>
  ): DeviceAuth {
    let structure = encodedStructure as DeviceAuthStructure

    if (encodedStructure instanceof Map) {
      structure = {
        deviceMac: encodedStructure.get('deviceMac') as DeviceAuthStructure['deviceMac'],
        deviceSignature: encodedStructure.get('deviceSignature') as DeviceAuthStructure['deviceSignature'],
      }
    }

    return new DeviceAuth({
      deviceSignature: structure.deviceSignature
        ? DeviceSignature.fromEncodedStructure(structure.deviceSignature)
        : undefined,
      deviceMac: structure.deviceMac ? DeviceMac.fromEncodedStructure(structure.deviceMac) : undefined,
    })
  }
}
