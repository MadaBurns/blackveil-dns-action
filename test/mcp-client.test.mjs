import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMcpClient, parseRetryAfterMs, isRetryableStatus, McpProtocolError, MAX_RETRY_AFTER_MS } from '../lib/mcp-client.mjs';

function jsonResponse(body, { status = 200, headers = {} } = {}) {
	return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** Build a client whose fetch replays a scripted list of responses/errors. */
function scripted(steps, overrides = {}) {
	const calls = [];
	const sleeps = [];
	const fetchImpl = async (url, init) => {
		calls.push({ url, init, body: JSON.parse(init.body) });
		const step = steps.shift();
		if (!step) throw new Error('no scripted response left');
		if (step instanceof Error) throw step;
		return typeof step === 'function' ? step() : step;
	};
	const client = createMcpClient({
		endpoint: 'https://example.test/mcp',
		userAgent: 'test/0',
		fetchImpl,
		sleep: async (ms) => {
			sleeps.push(ms);
		},
		backoffMs: 1000,
		...overrides,
	});
	return { client, calls, sleeps };
}

const initOk = () => jsonResponse({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'S', version: '1' } } }, { headers: { 'mcp-session-id': 'sess-1' } });

test('parseRetryAfterMs handles seconds, HTTP dates, garbage and clamps', () => {
	assert.equal(parseRetryAfterMs('5'), 5000);
	assert.equal(parseRetryAfterMs('0'), 0);
	assert.equal(parseRetryAfterMs('3600'), MAX_RETRY_AFTER_MS);
	const now = Date.parse('Wed, 21 Oct 2026 07:28:00 GMT');
	assert.equal(parseRetryAfterMs('Wed, 21 Oct 2026 07:28:10 GMT', now), 10_000);
	assert.equal(parseRetryAfterMs('Wed, 21 Oct 2026 07:27:00 GMT', now), 0);
	assert.equal(parseRetryAfterMs('soon'), null);
	assert.equal(parseRetryAfterMs(null), null);
});

test('isRetryableStatus', () => {
	assert.equal(isRetryableStatus(429), true);
	assert.equal(isRetryableStatus(408), true);
	assert.equal(isRetryableStatus(502), true);
	assert.equal(isRetryableStatus(400), false);
	assert.equal(isRetryableStatus(401), false);
	assert.equal(isRetryableStatus(404), false);
});

test('initialize negotiates protocol, captures session and sends both on later calls', async () => {
	const { client, calls } = scripted([
		initOk(),
		jsonResponse({ jsonrpc: '2.0', id: 2, result: { content: [{ type: 'text', text: 'hi' }] } }),
	]);
	const init = await client.initialize({ name: 'x', version: '1' });
	assert.equal(init.protocolVersion, '2025-06-18');
	assert.equal(init.serverInfo.name, 'S');
	assert.equal(calls[0].init.headers['Mcp-Session-Id'], undefined);
	assert.equal(calls[0].body.params.protocolVersion, '2025-06-18');

	await client.callTool('scan_domain', { domain: 'a.com' });
	assert.equal(calls[1].init.headers['Mcp-Session-Id'], 'sess-1');
	assert.equal(calls[1].init.headers['MCP-Protocol-Version'], '2025-06-18');
	assert.equal(calls[1].init.headers['User-Agent'], 'test/0');
	assert.equal(calls[1].body.method, 'tools/call');
	assert.deepEqual(calls[1].body.params, { name: 'scan_domain', arguments: { domain: 'a.com' } });
	assert.ok(calls[1].init.signal instanceof AbortSignal);
});

test('sends bearer token only when an api key is configured', async () => {
	const a = scripted([initOk()], { apiKey: 'k-123' });
	await a.client.initialize({});
	assert.equal(a.calls[0].init.headers.Authorization, 'Bearer k-123');
	const b = scripted([initOk()]);
	await b.client.initialize({});
	assert.equal(b.calls[0].init.headers.Authorization, undefined);
});

test('429 honours retry-after once (no double sleep) and then succeeds', async () => {
	const { client, calls, sleeps } = scripted([
		new Response('slow down', { status: 429, headers: { 'retry-after': '7' } }),
		initOk(),
	]);
	await client.initialize({});
	assert.equal(calls.length, 2);
	assert.deepEqual(sleeps, [7000]);
});

test('5xx retries with linear backoff; network errors retry too', async () => {
	const { client, calls, sleeps } = scripted([
		new Response('boom', { status: 503 }),
		new TypeError('fetch failed'),
		initOk(),
	]);
	await client.initialize({});
	assert.equal(calls.length, 3);
	assert.deepEqual(sleeps, [1000, 2000]);
});

test('gives up after maxAttempts with the last error', async () => {
	const { client, calls } = scripted([new Response('a', { status: 500 }), new Response('b', { status: 502 }), new Response('c', { status: 503 })]);
	await assert.rejects(client.initialize({}), /failed after 3 attempt\(s\): HTTP 503 — c/);
	assert.equal(calls.length, 3);
});

test('4xx other than 408/429 is not retried', async () => {
	const { client, calls } = scripted([new Response('nope', { status: 401 })]);
	await assert.rejects(client.initialize({}), (err) => err instanceof McpProtocolError && err.status === 401 && /HTTP 401 — nope/.test(err.message));
	assert.equal(calls.length, 1);
});

test('JSON-RPC errors are not retried', async () => {
	const { client, calls } = scripted([jsonResponse({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'bad params' } })]);
	await assert.rejects(client.initialize({}), (err) => err instanceof McpProtocolError && err.code === -32602);
	assert.equal(calls.length, 1);
});

test('timeout is surfaced as a transient error and retried', async () => {
	const timeoutErr = new Error('aborted');
	timeoutErr.name = 'TimeoutError';
	const { client, calls } = scripted([timeoutErr, initOk()], { timeoutMs: 5000 });
	await client.initialize({});
	assert.equal(calls.length, 2);
});

test('callTool surfaces isError results as protocol errors', async () => {
	const { client } = scripted([
		initOk(),
		jsonResponse({ jsonrpc: '2.0', id: 2, result: { isError: true, content: [{ type: 'text', text: 'Error: invalid domain' }] } }),
	]);
	await client.initialize({});
	await assert.rejects(client.callTool('scan_domain', {}), /scan_domain returned an error: Error: invalid domain/);
});
