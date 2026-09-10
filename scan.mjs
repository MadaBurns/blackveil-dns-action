#!/usr/bin/env node

/**
 * Blackveil DNS Security Scanner — GitHub Action entry point.
 *
 * Pure Node.js (no dependencies). Talks to the Blackveil DNS MCP server over
 * JSON-RPC 2.0 and enforces a minimum grade. Reporting logic lives in ./lib so
 * it can be unit-tested without network access.
 */

import { createMcpClient, McpProtocolError } from './lib/mcp-client.mjs';
import { parseScanResult } from './lib/parse.mjs';
import { normalizeMinimumGrade, meetsMinimumGrade } from './lib/grades.mjs';
import { buildSummaryMarkdown } from './lib/summary.mjs';
import { pathToFileURL } from 'node:url';
import { setOutput, writeSummary, logError, logWarning } from './lib/github.mjs';

export const ACTION_VERSION = '1.4.0';
export const USER_AGENT = `blackveil-dns-action/${ACTION_VERSION}`;
export const REPO_URL = 'https://github.com/MadaBurns/blackveil-dns-action';
export const DEFAULT_ENDPOINT = 'https://dns-mcp.blackveilsecurity.com/mcp';

/** Must match the server's ProfileSchema (bv-mcp src/schemas/primitives.ts). */
export const VALID_PROFILES = Object.freeze([
	'auto',
	'mail_enabled',
	'enterprise_mail',
	'non_mail',
	'web_only',
	'minimal',
	'authoritative_dns_infra',
]);

function parseBoolean(value, fallback) {
	if (value == null || String(value).trim() === '') return fallback;
	const v = String(value).trim().toLowerCase();
	if (['true', '1', 'yes', 'on'].includes(v)) return true;
	if (['false', '0', 'no', 'off'].includes(v)) return false;
	throw new Error(`Expected a boolean, got "${value}"`);
}

/**
 * Normalise and sanity-check the `domain` input. The server performs the real
 * validation; this only catches the common copy-paste mistakes (URL, whitespace)
 * so the error names the input instead of surfacing a server-side rejection.
 */
export function normalizeDomain(input) {
	const domain = String(input ?? '').trim().toLowerCase().replace(/\.$/, '');
	if (!domain) throw new Error('Missing required input: domain');
	if (/[\s/:@]/.test(domain) || !domain.includes('.')) {
		throw new Error(`Invalid domain "${domain}": provide a bare hostname such as example.com (no scheme, path or port)`);
	}
	return domain;
}

/** Read and validate all inputs from the environment. Throws on invalid input. */
export function readInputs(env = process.env) {
	const domain = normalizeDomain(env.INPUT_DOMAIN);
	const minimum = normalizeMinimumGrade(env.INPUT_MINIMUM_GRADE);
	const profile = (env.INPUT_PROFILE || 'auto').toLowerCase().trim();
	if (!VALID_PROFILES.includes(profile)) {
		throw new Error(`Invalid profile: "${profile}". Must be one of: ${VALID_PROFILES.join(', ')}`);
	}
	const endpoint = (env.INPUT_ENDPOINT || DEFAULT_ENDPOINT).trim();
	if (!/^https:\/\//i.test(endpoint)) {
		throw new Error(`Invalid endpoint "${endpoint}": must be an https:// URL (the API key is sent as a bearer token)`);
	}
	return {
		domain,
		minimumGrade: minimum.grade,
		minimumGradeWarning: minimum.warning,
		profile,
		apiKey: (env.INPUT_API_KEY || '').trim(),
		endpoint,
		forceRefresh: parseBoolean(env.INPUT_FORCE_REFRESH, false),
		failOnInconclusive: parseBoolean(env.INPUT_FAIL_ON_INCONCLUSIVE, true),
	};
}

/**
 * Decide the step outcome for a parsed result.
 *
 * @returns {{ passed: boolean, exitCode: number, message: string | null, level: 'error' | 'warning' | null }}
 */
export function evaluate(result, inputs) {
	if (!result.measured) {
		const reason = result.evidenceNote || result.maturity || 'the scan produced no gradeable evidence';
		const message = `Domain ${inputs.domain} could not be graded: ${reason}`;
		return inputs.failOnInconclusive
			? { passed: false, exitCode: 1, message, level: 'error' }
			: { passed: false, exitCode: 0, message: `${message} (fail-on-inconclusive is false, not failing the job)`, level: 'warning' };
	}
	const passed = meetsMinimumGrade(result.grade, inputs.minimumGrade);
	return passed
		? { passed: true, exitCode: 0, message: null, level: null }
		: {
				passed: false,
				exitCode: 1,
				message: `DNS security grade ${result.grade} (${result.score}/100) is below minimum ${inputs.minimumGrade}`,
				level: 'error',
			};
}

export function emitOutputs(result, verdict) {
	setOutput('score', result.measured ? result.score : '');
	setOutput('grade', result.measured ? result.grade : '');
	setOutput('measured', result.measured);
	setOutput('passed', verdict.passed);
	setOutput('maturity', result.maturity);
	setOutput('scoring-profile', result.scoringProfile ?? '');
	setOutput('finding-counts', result.findingCounts ? JSON.stringify(result.findingCounts) : '');
	setOutput('interaction-effects', result.interactionEffects.length > 0 ? JSON.stringify(result.interactionEffects) : '');
	setOutput('percentile-rank', result.percentileRank ?? '');
	setOutput('spoofability-score', result.spoofabilityScore ?? '');
	setOutput('report-url', result.reportUrl ?? '');
	setOutput('cached', result.cached);
}

async function main() {
	let inputs;
	try {
		inputs = readInputs();
	} catch (err) {
		logError(err.message);
		return 1;
	}
	if (inputs.minimumGradeWarning) logWarning(inputs.minimumGradeWarning);

	console.log(`Scanning ${inputs.domain} via ${inputs.endpoint} ...`);
	console.log(`Minimum grade: ${inputs.minimumGrade}`);
	if (inputs.profile !== 'auto') console.log(`Scoring profile: ${inputs.profile}`);
	if (inputs.forceRefresh) console.log('Bypassing the server-side scan cache');
	if (inputs.apiKey) console.log('Using authenticated access');

	const client = createMcpClient({
		endpoint: inputs.endpoint,
		apiKey: inputs.apiKey,
		userAgent: USER_AGENT,
		log: (msg) => console.log(msg),
	});

	let toolResult;
	try {
		const { serverInfo, protocolVersion } = await client.initialize({ name: 'blackveil-dns-action', version: ACTION_VERSION });
		console.log(`MCP session initialized (server ${serverInfo?.name ?? 'unknown'} ${serverInfo?.version ?? ''}, protocol ${protocolVersion})`);

		const args = { domain: inputs.domain, format: 'full' };
		if (inputs.profile !== 'auto') args.profile = inputs.profile;
		if (inputs.forceRefresh) args.force_refresh = true;

		toolResult = await client.callTool('scan_domain', args);
	} catch (err) {
		const prefix = err instanceof McpProtocolError ? 'Scan rejected' : 'Scan failed';
		logError(`${prefix}: ${err.message}`);
		return 1;
	}

	const result = parseScanResult(toolResult);
	const verdict = evaluate(result, inputs);

	const scoreText = result.measured ? `${result.grade} (${result.score}/100)` : 'not measured';
	console.log(`\nScan complete: ${scoreText} — Maturity: ${result.maturity} — Profile: ${result.scoringProfile ?? inputs.profile} — Source: ${result.source}`);
	console.log(`Minimum grade: ${inputs.minimumGrade} — ${verdict.passed ? 'PASSED' : result.measured ? 'FAILED' : 'INCONCLUSIVE'}`);

	emitOutputs(result, verdict);
	writeSummary(
		buildSummaryMarkdown(result, {
			domain: inputs.domain,
			minimumGrade: inputs.minimumGrade,
			passed: verdict.passed,
			requestedProfile: inputs.profile,
			repoUrl: REPO_URL,
		}),
	);

	if (verdict.message) {
		if (verdict.level === 'error') logError(verdict.message);
		else logWarning(verdict.message);
	}
	if (verdict.exitCode === 0 && verdict.passed) console.log('\nDNS security check passed.');
	return verdict.exitCode;
}

// Only run when executed directly (so tests can import the helpers above).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	main()
		.then((code) => {
			process.exitCode = code;
		})
		.catch((err) => {
			logError(`Unexpected error: ${err?.stack ?? err}`);
			process.exitCode = 1;
		});
}
