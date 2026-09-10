/**
 * GitHub Actions runtime helpers: outputs, job summary, and workflow commands.
 */

import { appendFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

/** Escape a value for use in a `::command::` message (per the Actions toolkit). */
function escapeCommandData(value) {
	return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

export function logError(message) {
	console.error(`::error::${escapeCommandData(message)}`);
}

export function logWarning(message) {
	console.log(`::warning::${escapeCommandData(message)}`);
}

export function logNotice(message) {
	console.log(`::notice::${escapeCommandData(message)}`);
}

/**
 * Set a step output. Uses the heredoc form so values containing newlines or
 * `=` are written safely. Falls back to a plain log line outside of Actions.
 */
export function setOutput(key, value, env = process.env) {
	const outputFile = env.GITHUB_OUTPUT;
	const text = value == null ? '' : String(value);
	if (!outputFile) {
		console.log(`[output] ${key}=${text}`);
		return;
	}
	const delimiter = `ghadelimiter_${randomBytes(8).toString('hex')}`;
	appendFileSync(outputFile, `${key}<<${delimiter}\n${text}\n${delimiter}\n`);
}

export function writeSummary(markdown, env = process.env) {
	const summaryFile = env.GITHUB_STEP_SUMMARY;
	if (summaryFile) {
		appendFileSync(summaryFile, `${markdown}\n`);
	} else {
		console.log(markdown);
	}
}
