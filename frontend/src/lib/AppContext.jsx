import { createContext, useContext } from 'react'

// The utilities every panel shares: the request wrapper (operator key
// attached), the busy/agent-card lifecycle, and the notice/feed channels.
// Data still arrives via props — the context carries behaviour, not state,
// so each component's inputs stay visible in its JSX.
export const AppContext = createContext(null)
export const useApp = () => useContext(AppContext)
