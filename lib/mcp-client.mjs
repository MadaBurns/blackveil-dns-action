/**
 * Minimal MCP Streamable-HTTP client (JSON-RPC 2.0 over POST) with a
 * conservative retry policy. No dependencies — uses the built-in fetch.
 */

export const PROTOCOL_VERSION = '2025-06-18';
export const DEFAULT_MAX_ATTEMPTS = 3;
export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_BACKOFF_MS = 3_000;
export const MAX_RETRY_AFTER_MS = 60_000;

/** Non-retryable protocol failure (JSON-RPC error, 4xx other than 408/429). */
export class McpProtocolError extends Error {
	constructor(message, { status, code } = {}) {
		super(message);
		this.name = 'McpProtocolError';
		this.status = status;
		this.code = code;
	}
}

/**
 * Parse a Retry-After header (delay-seconds or HTTP-date) into milliseconds,
 * clamped to [0, MAX_RETRY_AFTER_MS]. Returns null when absent/unparseable.
 */
export function parseRetryAfterMs(value, now = Date.now()) {
	if (!value) return null;
	const trimmed = String(value).trim();
	let ms;
	if (/^\d+$/.test(trimmed)) {
		ms = parseInt(trimmed, 10) * 1000;
	} else {
		const date = Date.parse(trimmed);
		if (Number.isNaN(date)) return null;
		ms = date - now;
	}
	return Math.min(Math.max(ms, 0), MAX_RETRY_AFTER_MS);
}

/** Whether an HTTP status is worth retrying. */
export function isRetryableStatus(status) {
	return status === 408 || status === 429 || status >= 500;
}

function defaultSleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @param {object} options
 * @param {string} options.endpoint
 * @param {string} [options.apiKey]
 * @param {string} options.userAgent
 * @param {number} [options.timeoutMs]
 * @param {number} [options.maxAttempts]
 * @param {number} [options.backoffMs]
 * @param {typeof fetch} [options.fetchImpl]
 * @param {(ms: number) => Promise<void>} [options.sleep]
 * @param {(msg: string) => void} [options.log]
 */
export function createMcpClient(options) {
	const {
		endpoint,
		apiKey = '',
		userAgent,
		timeoutMs = DEFAULT_TIMEOUT_MS,
		maxAttempts = DEFAULT_MAX_ATTEMPTS,
		backoffMs = DEFAULT_BACKOFF_MS,
		fetchImpl = globalThis.fetch,
		sleep = defaultSleep,
		log = () => {},
	} = options;

	let sessionId;
	let negotiatedVersion;
	let idCounter = 0;

	function headers() {
		const h = {
			'Content-Type': 'application/json',
			Accept: 'application/json',
			'User-Agent': userAgent,
		};
		if (sessionId) h['Mcp-Session-Id'] = sessionId;
		if (negotiatedVersion) h['MCP-Protocol-Version'] = negotiatedVersion;
		if (apiKey) h.Authorization = `Bearer ${apiKey}`;
		return h;
	}

	async function request(method, params) {
		const body = JSON.stringify({ jsonrpc: '2.0', id: ++idCounter, method, params });
		let lastError;

		for (let attempt = 1; attempt <= maxAttempts; attempt++) {
			if (attempt > 1) {
				log(`Retrying ${method} (attempt ${attempt}/${maxAttempts})...`);
			}

			let response;
			try {
				response = await fetchImpl(endpoint, {
					method: 'POST',
					headers: headers(),
					body,
					signal: AbortSignal.timeout(timeoutMs),
				});
			} catch (err) {
				// Network failure or timeout — transient.
				lastError = err?.name === 'TimeoutError' ? new Error(`Request timed out after ${timeoutMs / 1000}s`) : err;
				if (attempt < maxAttempts) await sleep(backoffMs * attempt);
				continue;
			}

			if (!response.ok) {
				const text = await response.text().catch(() => '');
				const detail = text ? ` — ${text.slice(0, 300)}` : '';
				if (!isRetryableStatus(response.status)) {
					throw new McpProtocolError(`HTTP ${response.status}${detail}`, { status: response.status });
				}
				lastError = new Error(`HTTP ${response.status}${detail}`);
				if (attempt < maxAttempts) {
					const retryAfter = parseRetryAfterMs(response.headers.get('retry-after'));
					const delay = retryAfter ?? backoffMs * attempt;
					log(`${response.status === 429 ? 'Rate limited' : `HTTP ${response.status}`}. Waiting ${Math.ceil(delay / 1000)}s...`);
					await sleep(delay);
				}
				continue;
			}

			let json;
			try {
				json = await response.json();
			} catch (err) {
				lastError = new Error(`Invalid JSON response: ${err.message}`);
				if (attempt < maxAttempts) await sleep(backoffMs * attempt);
				continue;
			}

			if (json?.error) {
				throw new McpProtocolError(`JSON-RPC error ${json.error.code}: ${json.error.message}`, { code: json.error.code });
			}

			const newSession = response.headers.get('mcp-session-id');
			if (newSession) sessionId = newSession;
			return json.result;
		}

		throw new Error(`MCP request "${method}" failed after ${maxAttempts} attempt(s): ${lastError?.message ?? 'unknown error'}`);
	}

	return {
		/** Perform the `initialize` handshake. Returns the server's `serverInfo`. */
		async initialize(clientInfo) {
			const result = await request('initialize', {
				protocolVersion: PROTOCOL_VERSION,
				capabilities: {},
				clientInfo,
			});
			negotiatedVersion = typeof result?.protocolVersion === 'string' ? result.protocolVersion : PROTOCOL_VERSION;
			return { serverInfo: result?.serverInfo ?? null, protocolVersion: negotiatedVersion };
		},

		/** Call a tool; returns the raw `{ content, structuredContent?, isError? }` result. */
		async callTool(name, args) {
			const result = await request('tools/call', { name, arguments: args });
			if (!result || typeof result !== 'object') {
				throw new Error(`Empty response from ${name}`);
			}
			if (result.isError) {
				const text = Array.isArray(result.content) ? result.content.map((c) => c?.text ?? '').join('\n') : '';
				throw new McpProtocolError(`${name} returned an error: ${text.trim() || 'no details'}`);
			}
			return result;
		},

		get sessionId() {
			return sessionId;
		},
		get protocolVersion() {
			return negotiatedVersion;
		},
	};
}
