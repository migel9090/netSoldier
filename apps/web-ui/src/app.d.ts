declare global {
  namespace App {
    interface Locals {
      /** Session actor label, set by hooks.server.ts when authenticated. */
      actor?: string
    }
  }
}

export {}
