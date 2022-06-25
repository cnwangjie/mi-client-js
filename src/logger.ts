export interface Logger {
  debug(msg: string): any
  info(msg: string): any
  warn(msg: string): any
  error(msg: string): any
}

export const defaultLogger: Logger = {
  debug: console.debug,
  info: console.log,
  warn: console.warn,
  error: console.error,
}
