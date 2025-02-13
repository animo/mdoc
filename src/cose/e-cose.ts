export function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && !Array.isArray(value) && typeof value === 'object'
}

class UnknownCauseError extends Error {
  [key: string]: unknown
}

export function getCauseFromUnknown(cause: unknown): Error | undefined {
  if (cause instanceof Error) {
    return cause
  }

  const type = typeof cause
  if (type === 'undefined' || type === 'function' || cause === null) {
    return undefined
  }

  // Primitive types just get wrapped in an error
  if (type !== 'object') {
    return new Error(String(cause))
  }

  // If it's an object, we'll create a synthetic error
  if (isObject(cause)) {
    const err = new UnknownCauseError()
    for (const key in cause) {
      err[key] = cause[key]
    }
    return err
  }

  return undefined
}

export const isCoseError = (cause: unknown): cause is CoseError => {
  if (cause instanceof CoseError) {
    return true
  }
  if (cause instanceof Error && cause.name === 'CoseError') {
    // https://github.com/trpc/trpc/pull/4848
    return true
  }

  return false
}

export function getCoseErrorFromUnknown(cause: unknown): CoseError {
  if (isCoseError(cause)) {
    return cause
  }

  const coseError = new CoseError({
    code: 'INTERNAL_SERVER_ERROR',
    cause,
  })

  // Inherit stack from error
  if (cause instanceof Error && cause.stack) {
    coseError.stack = cause.stack
  }

  return coseError
}

export type COSE_ERROR_CODE =
  | 'INTERNAL_SERVER_ERROR'
  | 'COSE_UNSUPPORTED_MAC'
  | 'COSE_ALG_NOT_ALLOWED'
  | 'COSE_INVALID_SIGNATURE'
  | 'COSE_INVALID_ALG'
  | 'COSE_UNSUPPORTED_ALG'

export class CoseError extends Error {
  // @ts-ignore override doesn't work in all environments due to "This member cannot have an 'override' modifier because it is not declared in the base class 'Error'"
  public override readonly cause?: Error
  public readonly code

  constructor(opts: {
    message?: string
    code: COSE_ERROR_CODE
    cause?: unknown
  }) {
    const cause = getCauseFromUnknown(opts.cause)
    const message = opts.message ?? cause?.message ?? opts.code

    // @ts-ignore https://github.com/tc39/proposal-error-cause
    super(message, { cause })

    this.code = opts.code
    this.name = 'CoseError'

    if (!this.cause) {
      // < ES2022 / < Node 16.9.0 compatability
      this.cause = cause
    }
  }
}
