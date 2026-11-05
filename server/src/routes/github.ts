import { Router } from 'express';
import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { z } from 'zod';
import { decrypt, encrypt } from '../lib/crypto.js';
import { getSetting, setSetting } from '../db/index.js';
import { requireAuth } from '../middleware/requireAuth.js';

export const githubRouter = Router();
// Only the OAuth callback is reachable without a dashboard Bearer token; its one-time state is the CSRF protection.
githubRouter.use((req, res, next) => req.path === '/callback' ? next() : requireAuth(req, res, next));
const TOKEN_SETTING = 'github_oauth_token_v1';
const states = new Map<string, { createdAt: number }>();
const STATE_TTL_MS = 10 * 60 * 1000;
const API = 'https://api.github.com';

function redirectUri(): string {
  return process.env.GITHUB_REDIRECT_URI ||
    `${process.env.PUBLIC_URL || 'https://freellmapi-production-6b62.up.railway.app'}/api/github/callback`;
}
function readToken(): string | null {
  const raw = getSetting(TOKEN_SETTING);
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as { encrypted: string; iv: string; authTag: string };
    return decrypt(value.encrypted, value.iv, value.authTag);
  } catch {
    return null;
  }
}
type GitHubResponse = Record<string, any>;

async function github(path: string, init: RequestInit = {}): Promise<GitHubResponse> {
  const token = readToken();
  if (!token) throw new Error('GitHub is not connected.');
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  });
  const body: GitHubResponse = await response.json().catch((): GitHubResponse => ({}));
  if (!response.ok) {
    const error = new Error(body.message || `GitHub returned ${response.status}`);
    (error as Error & { status?: number }).status = response.status;
    throw error;
  }
  return body;
}
function sendError(res: Response, error: unknown) {
  const status = (error as { status?: number })?.status || 400;
  res.status(status).json({ error: { message: error instanceof Error ? error.message : 'GitHub request failed', type: 'github_error' } });
}

// The start endpoint is mounted behind requireAuth. State is random, short-lived,
// one-use, and held server-side; the callback never trusts a caller-supplied URL.
githubRouter.get('/connect', (_req: Request, res: Response) => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId || !process.env.GITHUB_CLIENT_SECRET) {
    res.status(503).json({ error: { message: 'GitHub OAuth is not configured on the server.', type: 'github_not_configured' } });
    return;
  }
  const state = crypto.randomBytes(32).toString('hex');
  states.set(state, { createdAt: Date.now() });
  for (const [key, value] of states) if (Date.now() - value.createdAt > STATE_TTL_MS) states.delete(key);
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri(), scope: 'repo read:user', state });
  res.json({ url: `https://github.com/login/oauth/authorize?${params}` });
});

githubRouter.get('/callback', async (req: Request, res: Response) => {
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const pending = states.get(state);
  states.delete(state);
  if (!pending || Date.now() - pending.createdAt > STATE_TTL_MS || typeof req.query.code !== 'string') {
    res.status(400).send('GitHub connection expired or invalid. Return to FreeLLMAPI and try again.');
    return;
  }
  try {
    const exchange = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: req.query.code, redirect_uri: redirectUri(), state }),
    });
    const payload = await exchange.json() as { access_token?: string; error_description?: string };
    if (!exchange.ok || !payload.access_token) throw new Error(payload.error_description || 'GitHub authorization failed.');
    const secret = encrypt(payload.access_token);
    setSetting(TOKEN_SETTING, JSON.stringify(secret));
    res.redirect('/?github=connected');
  } catch (error) {
    res.status(400).send(error instanceof Error ? error.message : 'GitHub authorization failed.');
  }
});

githubRouter.get('/status', (_req, res) => {
  res.json({ connected: !!readToken(), configured: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) });
});
githubRouter.post('/disconnect', (_req, res) => {
  setSetting(TOKEN_SETTING, '');
  res.json({ connected: false });
});
githubRouter.get('/repos', async (_req, res) => {
  try { res.json(await github('/user/repos?per_page=100&sort=updated')); } catch (e) { sendError(res, e); }
});
githubRouter.get('/repos/:owner/:repo', async (req, res) => {
  try { res.json(await github(`/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}`)); }
  catch (e) { sendError(res, e); }
});
githubRouter.get('/repos/:owner/:repo/tree', async (req, res) => {
  try {
    const repo = `/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}`;
    const branch = typeof req.query.ref === 'string' ? req.query.ref : (await github(repo)).default_branch;
    res.json(await github(`${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`));
  } catch (e) { sendError(res, e); }
});
githubRouter.get('/repos/:owner/:repo/file', async (req, res) => {
  const path = typeof req.query.path === 'string' ? req.query.path : '';
  if (!path || path.startsWith('/') || path.split('/').includes('..')) {
    res.status(400).json({ error: { message: 'A valid repository-relative file path is required.', type: 'invalid_request_error' } });
    return;
  }
  try {
    const result = await github(`/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}/contents/${path.split('/').map(encodeURIComponent).join('/')}${typeof req.query.ref === 'string' ? `?ref=${encodeURIComponent(req.query.ref)}` : ''}`);
    if (result.encoding !== 'base64' || typeof result.content !== 'string') {
      res.status(415).json({ error: { message: 'This endpoint only supports text files.', type: 'unsupported_file' } });
      return;
    }
    res.json({ path, sha: result.sha, content: Buffer.from(result.content, 'base64').toString('utf8') });
  } catch (e) { sendError(res, e); }
});
const branchSchema = z.object({ branch: z.string().min(1).max(200).regex(/^[A-Za-z0-9._/-]+$/), base: z.string().min(1) }).strict();
githubRouter.post('/repos/:owner/:repo/branches', async (req, res) => {
  const parsed = branchSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: { message: 'Invalid branch details.', type: 'invalid_request_error' } }); return; }
  try {
    const repo = `/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}`;
    const base = await github(`${repo}/git/ref/heads/${encodeURIComponent(parsed.data.base)}`);
    res.json(await github(`${repo}/git/refs`, { method: 'POST', body: JSON.stringify({ ref: `refs/heads/${parsed.data.branch}`, sha: base.object.sha }) }));
  } catch (e) { sendError(res, e); }
});
const fileSchema = z.object({ path: z.string().min(1).max(500), content: z.string().max(1_000_000), message: z.string().min(1).max(500), branch: z.string().min(1), sha: z.string().optional() }).strict();
githubRouter.put('/repos/:owner/:repo/file', async (req, res) => {
  const parsed = fileSchema.safeParse(req.body);
  if (!parsed.success || parsed.data.path.startsWith('/') || parsed.data.path.split('/').includes('..')) {
    res.status(400).json({ error: { message: 'Invalid file change.', type: 'invalid_request_error' } }); return;
  }
  try {
    const p = parsed.data;
    const url = `/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}/contents/${p.path.split('/').map(encodeURIComponent).join('/')}`;
    res.json(await github(url, { method: 'PUT', body: JSON.stringify({ message: p.message, content: Buffer.from(p.content, 'utf8').toString('base64'), branch: p.branch, ...(p.sha ? { sha: p.sha } : {}) }) }));
  } catch (e) { sendError(res, e); }
});
const prSchema = z.object({ title: z.string().min(1).max(256), body: z.string().max(10000).optional(), head: z.string().min(1), base: z.string().min(1), draft: z.boolean().optional() }).strict();
githubRouter.post('/repos/:owner/:repo/pulls', async (req, res) => {
  const parsed = prSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: { message: 'Invalid pull request details.', type: 'invalid_request_error' } }); return; }
  try { res.status(201).json(await github(`/repos/${encodeURIComponent(req.params.owner)}/${encodeURIComponent(req.params.repo)}/pulls`, { method: 'POST', body: JSON.stringify(parsed.data) })); } catch (e) { sendError(res, e); }
});
