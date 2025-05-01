import type { BleOptions, BleOptionsStructure } from './ble-options'
import type { NfcOptions, NfcOptionsStructure } from './nfc-options'
import type { WifiOptions, WifiOptionsStructure } from './wifi-options'

export type RetrievalOptionsStructure = WifiOptionsStructure | BleOptionsStructure | NfcOptionsStructure
export type RetrievalOptions = WifiOptions | BleOptions | NfcOptions
