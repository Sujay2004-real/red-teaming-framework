import { useApp } from '../lib/AppContext'

// The agent crew the cards animate. `working` comes from the live request
// lifecycle; `done` reads saved state only, so a card never claims an agent
// finished work the backend has not recorded.
export default function CrewPanel({ crew, activeAgent, feed, onClearFeed }) {
  const { busy } = useApp()
  const workingAgent = crew.find(agent => agent.key === activeAgent)
  return <section className="panel crew-panel">
    <div className="panel-title"><div><span className="eyebrow">LIVE</span><h2>The agent crew</h2></div><span className={activeAgent ? 'tag good' : 'tag'}>{workingAgent ? `${workingAgent.name} is working…` : 'Standing by'}</span></div>
    <div className="crew">
      {crew.map(agent => <div className={`crew-card${activeAgent === agent.key ? ' working' : ''}${agent.done && activeAgent !== agent.key ? ' done' : ''}`} key={agent.key}>
        <span className="crew-avatar" aria-hidden="true">{agent.emoji}</span>
        <b>{agent.name}</b>
        <small>{activeAgent === agent.key ? agent.working : agent.done ? agent.doneText : agent.idle}</small>
      </div>)}
    </div>
    {!!feed.length && <div className="feed-wrap"><div className="panel-title"><h2>What just happened</h2><button className="secondary compact" onClick={onClearFeed} disabled={busy}>Clear</button></div>
      <ul className="feed">{feed.map((entry, i) => <li key={entry.at + '-' + i} className={entry.kind}><span className="feed-time">{new Date(entry.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>{entry.text}</li>)}</ul>
    </div>}
  </section>
}
