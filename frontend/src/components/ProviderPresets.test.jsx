import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import App from '../App'
import { setOperatorKey } from '../lib/api'

afterEach(() => { setOperatorKey(''); vi.unstubAllGlobals(); vi.restoreAllMocks() })
const response = data => Promise.resolve({ ok: true, status: 200, json: async () => structuredClone(data) })

async function openSettings(initial = {}) {
  setOperatorKey('test-operator-key')
  let saved = { api_base_url: '', model_name: '', gemini_configured: false, provider_ready: false, execution_mode: 'local', ...initial }
  const writes = []
  vi.stubGlobal('fetch', vi.fn((url, options) => {
    if (url.endsWith('/targets/') || url.endsWith('/capabilities')) return response([])
    if (url.includes('/catalog/')) return response({ items: [], total: 0, reported_total: 0 })
    if (url.endsWith('/settings')) {
      if (options?.method === 'PUT') {
        const payload = JSON.parse(options.body)
        writes.push(payload)
        const configured = !!payload.gemini_api_key || (saved.gemini_configured && !!payload.api_base_url && payload.api_base_url === saved.api_base_url)
        saved = { ...saved, api_base_url: payload.api_base_url, model_name: payload.model_name, gemini_configured: configured, provider_ready: !!(configured && payload.api_base_url && payload.model_name) }
      }
      return response(saved)
    }
    return response({ status: 'ok' })
  }))
  const user = userEvent.setup()
  render(<App />)
  await user.click(await screen.findByRole('button', { name: 'Settings', exact: true }))
  return { user, writes }
}

test.each([
  ['openai', 'https://api.openai.com/v1', 'gpt-5.4-mini', 'https://platform.openai.com/api-keys'],
  ['anthropic', 'https://api.anthropic.com/v1', 'claude-sonnet-4-6', 'https://platform.claude.com/settings/keys'],
  ['gemini', 'https://generativelanguage.googleapis.com/v1beta/openai', 'gemini-3.8-flash', 'https://aistudio.google.com/apikey'],
  ['openrouter', 'https://openrouter.ai/api/v1', 'openrouter/auto', 'https://openrouter.ai/settings/keys'],
  ['groq', 'https://api.groq.com/openai/v1', 'openai/gpt-oss-120b', 'https://console.groq.com/keys'],
])('%s can be configured by selecting the provider and pasting only its key', async (id, baseUrl, model, keyUrl) => {
  const { user, writes } = await openSettings()
  expect(screen.getByLabelText('Provider')).toHaveValue('local')
  await user.selectOptions(screen.getByLabelText('Provider'), id)
  expect(screen.getByRole('link', { name: 'Get an API key' })).toHaveAttribute('href', keyUrl)
  expect(screen.getByLabelText('Model name')).toHaveValue(model)
  const keyInput = screen.getByLabelText('API key', { exact: true })
  expect(keyInput).toHaveAttribute('type', 'password')
  await user.click(keyInput)
  await user.paste('  provider-test-secret  ')
  await user.click(screen.getByRole('button', { name: 'Save configuration' }))
  await waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]).toMatchObject({ api_base_url: baseUrl, model_name: model, gemini_api_key: 'provider-test-secret' })
  expect(writes[0]).not.toHaveProperty('provider_preset')
  await waitFor(() => expect(screen.getByLabelText('API key', { exact: true })).toHaveValue(''))
  expect(screen.getByLabelText('Provider')).toHaveValue(id)
  expect(await screen.findByText('Leave blank to keep the stored key.')).toBeInTheDocument()
  expect(JSON.stringify(localStorage)).not.toContain('provider-test-secret')
  expect(JSON.stringify(sessionStorage)).not.toContain('provider-test-secret')
})

test('loading a saved preset keeps its custom model and saves edits without re-entering the key', async () => {
  const { user, writes } = await openSettings({ api_base_url: 'https://api.openai.com/v1/', model_name: 'account-specific-model', gemini_configured: true, provider_ready: true })
  expect(screen.getByLabelText('Provider')).toHaveValue('openai')
  expect(screen.getByLabelText('Model name')).toHaveValue('account-specific-model')
  expect(screen.getByLabelText('API key', { exact: true })).not.toBeRequired()
  await user.clear(screen.getByLabelText('Model name'))
  await user.type(screen.getByLabelText('Model name'), 'another-model')
  await user.click(screen.getByRole('button', { name: 'Save configuration' }))
  await waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]).toMatchObject({ model_name: 'another-model', gemini_api_key: '', api_base_url: 'https://api.openai.com/v1/' })
})

test('switching providers discards an unsaved key and requires the new provider key', async () => {
  const { user, writes } = await openSettings({ api_base_url: 'https://api.openai.com/v1', model_name: 'saved-model', gemini_configured: true, provider_ready: true })
  await user.type(screen.getByLabelText('API key', { exact: true }), 'unsaved-openai-key')
  await user.selectOptions(screen.getByLabelText('Provider'), 'anthropic')
  expect(screen.getByLabelText('API key', { exact: true })).toHaveValue('')
  expect(screen.getByLabelText('API key', { exact: true })).toBeRequired()
  expect(screen.queryByText('Leave blank to keep the stored key.')).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Save configuration' }))
  expect(writes).toHaveLength(0)
  await user.click(screen.getByRole('button', { name: 'Assessments', exact: true }))
  await user.click(screen.getByRole('button', { name: 'Settings', exact: true }))
  expect(screen.getByLabelText('Provider')).toHaveValue('anthropic')
  await user.type(screen.getByLabelText('API key', { exact: true }), 'new-anthropic-key')
  await user.click(screen.getByRole('button', { name: 'Save configuration' }))
  await waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]).toMatchObject({ api_base_url: 'https://api.anthropic.com/v1', gemini_api_key: 'new-anthropic-key' })
})

test('custom endpoints remain editable and local mode submits a complete disconnection', async () => {
  const { user, writes } = await openSettings({ api_base_url: 'http://localhost:20128/v1', model_name: 'my-local-model', gemini_configured: true, provider_ready: true })
  expect(screen.getByLabelText('Provider')).toHaveValue('custom')
  expect(screen.getByLabelText('Base URL')).toBeVisible()
  expect(screen.getByLabelText('Model name')).toHaveValue('my-local-model')
  await user.type(screen.getByLabelText('API key', { exact: true }), 'unsaved-custom-key')
  await user.clear(screen.getByLabelText('Base URL'))
  await user.type(screen.getByLabelText('Base URL'), 'https://proxy.example/v1')
  expect(screen.getByLabelText('Base URL')).toHaveValue('https://proxy.example/v1')
  expect(screen.getByLabelText('API key', { exact: true })).toHaveValue('')
  await user.selectOptions(screen.getByLabelText('Provider'), 'local')
  expect(screen.queryByLabelText('API key', { exact: true })).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Save configuration' }))
  await waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]).toMatchObject({ api_base_url: '', model_name: '', gemini_api_key: '' })
  await waitFor(() => expect(screen.getByText('Fallback mode')).toBeInTheDocument())
  expect(screen.getByLabelText('Provider')).toHaveValue('local')
})

test('custom mode preserves preset values and editing its endpoint keeps keyboard focus', async () => {
  const { user } = await openSettings({ api_base_url: 'https://api.openai.com/v1', model_name: 'my-model' })
  await user.selectOptions(screen.getByLabelText('Provider'), 'custom')
  expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.openai.com/v1')
  expect(screen.getByLabelText('Model name')).toHaveValue('my-model')
  await user.type(screen.getByLabelText('Base URL'), '/proxy')
  expect(screen.getByLabelText('Base URL')).toHaveValue('https://api.openai.com/v1/proxy')
  expect(screen.getByLabelText('Base URL')).toHaveFocus()
})
