/**
 * Ambient type stubs for the dsh client peer packages.
 *
 * The marketplace client bundle compiles against a handful of
 * `@deepseek-ai/dsh-client-*` peer packages that the HOST provides at
 * runtime through its module `seed` table (see
 * `scripts/build-client.mjs` `external`). None of them are installed in
 * this repository, so `tsc -b tsconfig.client.json` needs an ambient
 * declaration to resolve the type-only imports.
 *
 * Only the surface this repo actually consumes is declared — keeping the
 * stub minimal makes it obvious what the real package must provide when
 * the workspace links it. Runtime behaviour is unaffected: esbuild
 * erases type-only imports, and the one value-level import
 * (`SecurityMonitorIcon`) only uses plain React createElement.
 */
declare module '@deepseek-ai/dsh-client-ui-slots' {
  /** Props the host's sidebar forwards to a `sidebar.panellist` icon
   *  entry. See the host sidebar
   *  in the harness workspace for the authoritative shape. */
  export interface SidebarPanellistIconProps {
    /** Requested edge length in px. */
    size: number
    /** Whether the panel is currently selected. */
    active: boolean
  }

  export type PropsRuntime<K extends string> = K extends 'sidebar.panellist'
    ? SidebarPanellistIconProps
    : Record<string, unknown>
}
