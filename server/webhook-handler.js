// Minimal orchestration webhook + enqueuer.
// Production notes: add robust retry, structured logging, rate limiting, and secure key storage.

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Octokit } = require('@octokit/rest');
const { createAppAuth } = require('@octokit/auth-app');
const IORedis = require('ioredis');
const Queue = require('bull');

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const REDIS_URL = process.env.REDIS_URL || 'redis://redis:6379';
const REDIS_NAMESPACE = 'agent-events';

if (!WEBHOOK_SECRET) {
  console.warn('Warning: WEBHOOK_SECRET not configured. Set WEBHOOK_SECRET env var.');
}

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

function verifySignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || !WEBHOOK_SECRET) return false;
  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
  } catch {
    return false;
  }
}

const redis = new IORedis(REDIS_URL);
const queue = new Queue(`${REDIS_NAMESPACE}:queue`, REDIS_URL);
const agentActionsQueue = new Queue(`${REDIS_NAMESPACE}:agent-actions`, REDIS_URL);

// Enqueue event with metadata for worker to consume
async function enqueueEvent(eventType, payload) {
  await queue.add({ eventType, payload }, { attempts: 5, backoff: 1000 });
}

// Enqueue agent action
async function enqueueAgentAction(agentId, actionPayload) {
  // actionPayload expected to include { action: string, repo?: { owner, name }, installationId?: number, params?: {} }
  await agentActionsQueue.add({ agentId, action: actionPayload }, { attempts: 5, backoff: 1000 });
}

// Helper to get installation token for a given installation id
async function getInstallationOctokit(installationId) {
  const appAuth = createAppAuth({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_PRIVATE_KEY,
  });

  const installationAuth = await appAuth({ type: 'installation', installationId });
  const octokit = new Octokit({ auth: installationAuth.token });
  return octokit;
}

app.post('/webhook', async (req, res) => {
  if (!verifySignature(req)) {
    res.status(401).send('invalid signature');
    return;
  }

  const event = req.headers['x-github-event'];
  const payload = req.body;
  try {
    // Filter interesting events and enqueue
    switch (event) {
      case 'issues':
      case 'pull_request':
      case 'push':
      case 'workflow_run':
      case 'pull_request_review':
        // Attach installation id if present (Apps)
        const installationId = payload.installation?.id || payload.repository?.owner?.id;
        await enqueueEvent(event, { payload, installationId });
        break;
      default:
        // ignore
        break;
    }
    res.status(200).send('ok');
  } catch (err) {
    console.error('enqueue error', err);
    res.status(500).send('error');
  }
});

// New API endpoint: POST /v1/agents/:agent_id/execute
// Accepts an AgentAction JSON payload and queues it for execution by the agent worker pool.
// Schema (informal): { action: "run_task", repo?: { owner, name }, installationId?: number, params?: {} }
app.post('/v1/agents/:agent_id/execute', async (req, res) => {
  // Optional: allow a separate auth method for API clients (e.g., bearer token). For now rely on webhook secret if provided.
  // NOTE: In production, enforce proper authentication (OIDC/JWT/API key) and rate limits.

  // If WEBHOOK_SECRET is set, verify signature header 'x-hub-signature-256' to avoid anonymous calls
  if (WEBHOOK_SECRET && !verifySignature(req)) {
    // If signature is missing, also allow an Authorization header with a bearer token in real deployments.
    res.status(401).json({ error: 'invalid signature or missing auth' });
    return;
  }

  const agentId = req.params.agent_id;
  const actionBody = req.body;

  if (!actionBody || !actionBody.action) {
    res.status(400).json({ error: 'invalid AgentAction: missing action field' });
    return;
  }

  try {
    await enqueueAgentAction(agentId, actionBody);
    res.status(200).json({ status: 'queued' });
  } catch (err) {
    console.error('enqueueAgentAction error', err);
    res.status(500).json({ error: 'failed to queue agent action' });
  }
});

app.listen(PORT, () => {
  console.log(`webhook server listening on ${PORT}`);
  console.log(`connected to redis ${REDIS_URL}`);
});
