declare global {
  namespace App {
    interface Locals {
      /** The verified session, set by hooks.server.ts when signed in. */
      session?: import('$lib/server/auth').Session
      /** Session actor label, set by hooks.server.ts when signed in. */
      actor?: string
    }
  }
}

export {}
