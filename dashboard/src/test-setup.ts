import '@testing-library/jest-dom/vitest'

// The test environment (vitest + jsdom on Node 22+) does not provide a working
// Web Storage: both the Node global `localStorage` and jsdom's
// `window.localStorage` are plain objects with no getItem/setItem/removeItem.
// The dashboard (v0.2.1) stores the operator's API key in localStorage, so we
// install a minimal in-memory Storage polyfill for the tests. Production code
// is untouched (real browsers have a fully-spec'd localStorage).
class MemStorage {
  private store = new Map<string, string>()
  get length() { return this.store.size }
  getItem(k: string) { return this.store.has(k) ? this.store.get(k)! : null }
  setItem(k: string, v: string) { this.store.set(k, String(v)) }
  removeItem(k: string) { this.store.delete(k) }
  clear() { this.store.clear() }
  key(i: number) { return Array.from(this.store.keys())[i] ?? null }
}

const polyfill = new MemStorage()
;(globalThis as any).localStorage = polyfill
;(globalThis as any).window ||= {}
;(globalThis as any).window.localStorage = polyfill