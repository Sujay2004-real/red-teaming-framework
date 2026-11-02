import '@testing-library/jest-dom/vitest'
import { cleanup, configure } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// jsdom has no layout or scrolling implementation; browser checks cover it.
Element.prototype.scrollIntoView = vi.fn()
afterEach(cleanup)
configure({ asyncUtilTimeout: 5000 })
