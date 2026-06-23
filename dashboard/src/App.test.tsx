// Dashboard smoke test (Phase 6.2) - renders App in its empty state and
// verifies the header + empty-state CTA are present. Does not hit the network.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

describe('App', () => {
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