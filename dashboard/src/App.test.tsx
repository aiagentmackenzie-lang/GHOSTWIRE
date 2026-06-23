// Dashboard smoke test (Phase 6.2) - renders App in its empty state and
// verifies the header + empty-state CTA are present. Does not hit the network.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import App from './App'

const KEY = 'ghostwire_api_key'

describe('App', () => {
  beforeEach(() => {
    localStorage.removeItem(KEY)
  })
  afterEach(() => {
    localStorage.removeItem(KEY)
  })

  it('renders the header and the empty-state CTA before any analysis', () => {
    render(<App />)
    expect(screen.getByText('GHOSTWIRE')).toBeInTheDocument()
    expect(screen.getByText(/Feed the wire/i)).toBeInTheDocument()
  })

  it('exposes an Analyze button that is disabled until a path is entered', () => {
    render(<App />)
    const btn = screen.getByRole('button', { name: /Analyze/i })
    expect(btn).toBeDisabled()
  })
})

describe('App API key prompt (v0.2.1)', () => {
  beforeEach(() => {
    localStorage.removeItem(KEY)
  })
  afterEach(() => {
    localStorage.removeItem(KEY)
  })

  it('renders the API key prompt when no key is stored', () => {
    render(<App />)
    expect(screen.getByText(/API key required/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/API key/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Connect/i })).toBeDisabled()
  })

  it('hides the prompt and shows Clear key once a key is in localStorage', () => {
    localStorage.setItem(KEY, 'sekret')
    render(<App />)
    expect(screen.queryByText(/API key required/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Clear key/i })).toBeInTheDocument()
  })

  it('persists the entered key to localStorage on Connect', () => {
    render(<App />)
    const input = screen.getByPlaceholderText(/API key/i) as HTMLInputElement
    fireEvent.change(input, { target: { value: '  tok-123  ' } })
    fireEvent.click(screen.getByRole('button', { name: /Connect/i }))
    expect(localStorage.getItem(KEY)).toBe('tok-123')
    expect(screen.queryByText(/API key required/i)).not.toBeInTheDocument()
  })
})