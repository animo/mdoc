import { MdlError } from './errors.js'

export interface VerificationAssessment {
  status: 'PASSED' | 'FAILED' | 'WARNING'
  category: 'DOCUMENT_FORMAT' | 'DEVICE_AUTH' | 'ISSUER_AUTH' | 'DATA_INTEGRITY'
  check: string
  reason?: string
}

export type VerificationCallback = (item: VerificationAssessment) => void

export const defaultVerificationCallback: VerificationCallback = (verification) => {
  if (verification.status !== 'FAILED') return
  throw new MdlError(verification.reason ?? verification.check)
}

export const onCategoryCheck = (onCheck: VerificationCallback, category: VerificationAssessment['category']) => {
  return (item: Omit<VerificationAssessment, 'category'>) => {
    onCheck({ ...item, category })
  }
}
