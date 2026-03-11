#!/usr/bin/env node

/**
 * Blackveil DNS Security Scanner — GitHub Action scan script.
 *
 * Pure Node.js (no dependencies). Uses the built-in fetch API (Node 18+).
 * Communicates with the Blackveil DNS MCP server via JSON-RPC 2.0.
 */

import { appendFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Grade ordering
// ---------------------------------------------------------------------------

const GRADE_ORDER = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'E', 'F'];

function gradeRank(grade) {
	const index = GRADE_ORDER.indexOf(grade);
	return index === -1 ? GRADE_ORDER.length : index;
}

function meetsMinimumGrade(actual, minimum) {
	return gradeRank(actual) <= gradeRank(minimum);
}

// ---------------------------------------------------------------------------
// GitHub Actions helpers
// ---------------------------------------------------------------------------

function setOutput(key, value) {
	const outputFile = process.env.GITHUB_OUTPUT;
	if (outputFile) {
		appendFileSync(outputFile, `${key}=${value}\n`);
	} else {
		// Fallback for local testing
		console.log(`::set-output name=${key}::${value}`);
	}
}

function writeSummary(markdown) {
	const summaryFile = process.env.GITHUB_STEP_SUMMARY;
	if (summaryFile) {
		appendFileSync(summaryFile, markdown + '\n');
	} else {
		console.log(markdown);
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

let rpcIdCounter = 0;

function jsonRpcRequest(method, params) {
	return {
		jsonrpc: '2.0',
		id: ++rpcIdCounter,
		method,
		...(params !== undefined ? { params } : {}),
	};
}

// ---------------------------------------------------------------------------
// MCP client
// ---------------------------------------------------------------------------

const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 3000;

async function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function mcpRequest(endpoint, method, params, sessionId) {
	const headers = {
		'Content-Type': 'application/json',
		Accept: 'application/json',
	};
	if (sessionId) {
		headers['Mcp-Session-Id'] = sessionId;
	}

	const body = JSON.stringify(jsonRpcRequest(method, params));

	let lastError;
	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		if (attempt > 0) {
			console.log(`Retrying (attempt ${attempt + 1}/${MAX_RETRIES + 1})...`);
			await sleep(RETRY_DELAY_MS * attempt);
		}

		try {
			const response = await fetch(endpoint, {
				method: 'POST',
				headers,
				body,
			});

			// Rate limited — retry after the suggested delay
			if (response.status === 429) {
				const retryAfter = parseInt(response.headers.get('retry-after') || '5', 10);
				console.log(`Rate limited. Waiting ${retryAfter}s...`);
				await sleep(retryAfter * 1000);
				lastError = new Error(`Rate limited (429)`);
				continue;
			}

			if (!response.ok) {
				const text = await response.text().catch(() => '');
				throw new Error(`HTTP ${response.status} — ${text.slice(0, 300)}`);
			}

			const newSessionId = response.headers.get('mcp-session-id') || sessionId;
			const json = await response.json();

			if (json.error) {
				throw new Error(`JSON-RPC error ${json.error.code}: ${json.error.message}`);
			}

			return { result: json.result, sessionId: newSessionId };
		} catch (err) {
			lastError = err;
			// Only retry on network/transient errors, not protocol errors
			if (err.message.includes('JSON-RPC error')) throw err;
		}
	}

	throw new Error(`MCP request failed after ${MAX_RETRIES + 1} attempts: ${lastError.message}`);
}

// ---------------------------------------------------------------------------
// Result parsing
// ---------------------------------------------------------------------------

/**
 * Try to extract structured JSON from the MCP content array.
 *
 * The MCP server (v1.1+) returns a second content block containing
 * machine-readable JSON wrapped in <!-- STRUCTURED_RESULT ... --> delimiters.
 * This is more resilient than regex-parsing the human-readable text report.
 */
function tryParseStructuredResult(contentArray) {
	if (!Array.isArray(contentArray)) return null;

	for (const item of contentArray) {
		const text = item.text || '';
		const match = text.match(/<!-- STRUCTURED_RESULT\n([\s\S]*?)\nSTRUCTURED_RESULT -->/);
		if (match) {
			try {
				const data = JSON.parse(match[1]);
				return {
					score: data.score,
					grade: data.grade,
					maturity: data.maturityLabel || 'Unknown',
					categories: Object.entries(data.categoryScores).map(([name, score]) => ({
						status: score >= 80 ? '\u2713' : score >= 50 ? '\u26A0' : '\u2717',
						name: name.toUpperCase(),
						score,
					})),
					findings: [], // populated below from text report
					findingCounts: data.findingCounts,
					rawText: contentArray.map((c) => c.text || '').join('\n'),
				};
			} catch {
				// Malformed JSON — fall through to regex parsing
			}
		}
	}

	return null;
}

/**
 * Parse the scan_domain text result returned by the MCP server using regex.
 *
 * Fallback for servers that don't include the structured JSON block.
 * The server returns a formatted text report (see format-report.ts).
 */
function parseScanResultFromText(text) {
	// Overall Score: 82/100 (B+)
	const scoreMatch = text.match(/Overall Score:\s*(\d+)\/100\s*\(([^)]+)\)/);
	const score = scoreMatch ? parseInt(scoreMatch[1], 10) : 0;
	const grade = scoreMatch ? scoreMatch[2].trim() : 'F';

	// Email Security Maturity: Stage 3 — Enforcing
	const maturityMatch = text.match(/Email Security Maturity:\s*Stage\s*\d+\s*[—–-]\s*(.+)/);
	const maturity = maturityMatch ? maturityMatch[1].trim() : 'Unknown';

	// Category scores table — matches lines like: ✓ SPF        85/100
	const categories = [];
	const categoryPattern = /\s*([✓⚠✗])\s+(\S+)\s+(\d+)\/100/g;
	let catMatch;
	while ((catMatch = categoryPattern.exec(text)) !== null) {
		categories.push({
			status: catMatch[1],
			name: catMatch[2],
			score: parseInt(catMatch[3], 10),
		});
	}

	// Findings — matches lines like: [CRITICAL] Some finding title
	const findings = [];
	const findingPattern = /\[(\w+)]\s+(.+)/g;
	let findMatch;
	while ((findMatch = findingPattern.exec(text)) !== null) {
		const severity = findMatch[1];
		const title = findMatch[2].trim();
		if (severity.toLowerCase() !== 'info') {
			findings.push({ severity, title });
		}
	}

	return { score, grade, maturity, categories, findings, rawText: text };
}

/**
 * Parse scan results from MCP content array.
 *
 * Tries structured JSON first (resilient), falls back to regex (legacy).
 * When structured JSON is used, findings are still extracted from the
 * text report since the structured block only carries severity counts.
 */
function parseScanResult(contentArray) {
	const rawText = Array.isArray(contentArray)
		? contentArray.map((c) => c.text || '').join('\n')
		: String(contentArray);

	// Try structured JSON first
	const structured = tryParseStructuredResult(contentArray);
	if (structured) {
		// Extract finding details from the text report for the summary table
		const textParsed = parseScanResultFromText(rawText);
		structured.findings = textParsed.findings;
		return structured;
	}

	// Fallback: regex parsing
	return parseScanResultFromText(rawText);
}

// ---------------------------------------------------------------------------
// Summary formatting
// ---------------------------------------------------------------------------

function gradeEmoji(grade) {
	if (grade === 'A+' || grade === 'A') return '\u{1F7E2}'; // green circle
	if (grade === 'B+' || grade === 'B') return '\u{1F7E1}'; // yellow circle
	if (grade === 'C+' || grade === 'C') return '\u{1F7E0}'; // orange circle
	return '\u{1F534}'; // red circle
}

function severityEmoji(severity) {
	switch (severity.toLowerCase()) {
		case 'critical':
			return '\u{1F6D1}'; // stop sign
		case 'high':
			return '\u{1F534}'; // red circle
		case 'medium':
			return '\u{1F7E0}'; // orange circle
		case 'low':
			return '\u{1F7E1}'; // yellow circle
		default:
			return '\u{2139}\u{FE0F}'; // info
	}
}

function categoryStatusEmoji(status) {
	if (status === '\u2713') return '\u2705'; // check mark
	if (status === '\u26A0') return '\u26A0\uFE0F'; // warning
	return '\u274C'; // cross mark
}

function buildSummaryMarkdown(result, domain, minimumGrade, passed) {
	const lines = [];

	lines.push(`## ${gradeEmoji(result.grade)} Blackveil DNS Security Scan: \`${domain}\``);
	lines.push('');
	lines.push('| Metric | Value |');
	lines.push('|--------|-------|');
	lines.push(`| **Score** | ${result.score}/100 |`);
	lines.push(`| **Grade** | **${result.grade}** |`);
	lines.push(`| **Maturity** | ${result.maturity} |`);
	lines.push(`| **Minimum Grade** | ${minimumGrade} |`);
	lines.push(`| **Result** | ${passed ? '\u2705 Passed' : '\u274C Failed'} |`);
	lines.push('');

	// Category scores
	if (result.categories.length > 0) {
		lines.push('### Category Scores');
		lines.push('');
		lines.push('| Category | Score | Status |');
		lines.push('|----------|-------|--------|');
		for (const cat of result.categories) {
			const emoji = categoryStatusEmoji(cat.status);
			lines.push(`| ${cat.name} | ${cat.score}/100 | ${emoji} |`);
		}
		lines.push('');
	}

	// Top findings
	if (result.findings.length > 0) {
		const topFindings = result.findings.slice(0, 10);
		lines.push('### Top Findings');
		lines.push('');
		for (const finding of topFindings) {
			lines.push(`- ${severityEmoji(finding.severity)} **[${finding.severity}]** ${finding.title}`);
		}
		if (result.findings.length > 10) {
			lines.push(`- _...and ${result.findings.length - 10} more_`);
		}
		lines.push('');
	} else {
		lines.push('### Findings');
		lines.push('');
		lines.push('\u2705 No security issues found.');
		lines.push('');
	}

	lines.push('---');
	lines.push('_Scanned by [Blackveil DNS Security Scanner](https://github.com/MadaBurns/blackveil-dns-action)_');

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
	const domain = process.env.INPUT_DOMAIN;
	const minimumGrade = (process.env.INPUT_MINIMUM_GRADE || 'C').toUpperCase().trim();
	const endpoint = process.env.INPUT_ENDPOINT || 'https://dns-mcp.blackveilsecurity.com/mcp';

	if (!domain) {
		console.error('::error::Missing required input: domain');
		process.exit(1);
	}

	// Validate minimum grade
	if (!GRADE_ORDER.includes(minimumGrade)) {
		console.error(`::error::Invalid minimum-grade: "${minimumGrade}". Must be one of: ${GRADE_ORDER.join(', ')}`);
		process.exit(1);
	}

	console.log(`Scanning ${domain} via ${endpoint} ...`);
	console.log(`Minimum grade: ${minimumGrade}`);

	// Step 1: Initialize MCP session
	let sessionId;
	try {
		const initResult = await mcpRequest(endpoint, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {
				name: 'blackveil-dns-action',
				version: '1.0.0',
			},
		});
		sessionId = initResult.sessionId;
		console.log('MCP session initialized');
	} catch (err) {
		console.error(`::error::Failed to initialize MCP session: ${err.message}`);
		process.exit(1);
	}

	// Step 2: Call scan_domain
	let scanContent;
	try {
		const scanResult = await mcpRequest(
			endpoint,
			'tools/call',
			{
				name: 'scan_domain',
				arguments: { domain },
			},
			sessionId,
		);

		// The result contains content array with text items
		scanContent = scanResult.result?.content;
		if (!scanContent || !Array.isArray(scanContent) || scanContent.length === 0) {
			throw new Error('Empty response from scan_domain');
		}

		if (scanResult.result?.isError) {
			const errorText = scanContent.map((item) => item.text || '').join('\n');
			throw new Error(`scan_domain returned error: ${errorText}`);
		}
	} catch (err) {
		console.error(`::error::Failed to scan domain: ${err.message}`);
		process.exit(1);
	}

	// Step 3: Parse results (tries structured JSON first, falls back to regex)
	const result = parseScanResult(scanContent);
	const passed = meetsMinimumGrade(result.grade, minimumGrade);

	console.log(`\nScan complete: ${result.grade} (${result.score}/100) — Maturity: ${result.maturity}`);
	console.log(`Minimum grade: ${minimumGrade} — ${passed ? 'PASSED' : 'FAILED'}`);

	// Step 4: Set outputs
	setOutput('score', String(result.score));
	setOutput('grade', result.grade);
	setOutput('maturity', result.maturity);
	setOutput('passed', String(passed));

	// Step 5: Write job summary
	const summaryMd = buildSummaryMarkdown(result, domain, minimumGrade, passed);
	writeSummary(summaryMd);

	// Step 6: Exit with appropriate code
	if (!passed) {
		console.error(`\n::error::DNS security grade ${result.grade} is below minimum ${minimumGrade}`);
		process.exit(1);
	}

	console.log('\nDNS security check passed.');
}

main().catch((err) => {
	console.error(`::error::Unexpected error: ${err.message}`);
	process.exit(1);
});
