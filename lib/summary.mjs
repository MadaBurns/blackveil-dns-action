/**
 * GitHub job-summary Markdown for a normalised scan result.
 */

const GRADE_EMOJI = { 'A+': '\u{1F7E2}', A: '\u{1F7E2}', B: '\u{1F7E1}', C: '\u{1F7E0}', D: '\u{1F534}', F: '\u{1F534}' };

const SEVERITY_EMOJI = {
	CRITICAL: '\u{1F6D1}',
	HIGH: '\u{1F534}',
	MEDIUM: '\u{1F7E0}',
	LOW: '\u{1F7E1}',
};

const CATEGORY_STATE = {
	ok: { emoji: '✅', label: '' },
	warn: { emoji: '⚠️', label: '' },
	fail: { emoji: '❌', label: '' },
	not_applicable: { emoji: '➖', label: 'N/A' },
	inconclusive: { emoji: '❔', label: 'Inconclusive' },
};

export const MAX_FINDINGS_IN_SUMMARY = 10;

function gradeEmoji(grade) {
	return GRADE_EMOJI[grade] ?? '⚪'; // white circle for ungraded
}

/** Escape the characters that would break a Markdown table cell. */
function cell(value) {
	return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function formatFindingCounts(counts) {
	if (!counts) return null;
	const parts = [];
	for (const key of ['critical', 'high', 'medium', 'low']) {
		if (counts[key]) parts.push(`${counts[key]} ${key}`);
	}
	return parts.length > 0 ? parts.join(', ') : 'None';
}

/**
 * @param {object} result   normalised result from parseScanResult
 * @param {object} ctx
 * @param {string} ctx.domain
 * @param {string} ctx.minimumGrade
 * @param {boolean} ctx.passed
 * @param {string} ctx.requestedProfile
 * @param {string} ctx.repoUrl
 */
export function buildSummaryMarkdown(result, ctx) {
	const { domain, minimumGrade, passed, requestedProfile, repoUrl } = ctx;
	const lines = [];

	lines.push(`## ${gradeEmoji(result.grade)} Blackveil DNS Security Scan: \`${cell(domain)}\``);
	lines.push('');

	if (!result.measured) {
		lines.push('> **Not measured.** The domain could not be graded, so this result is not a security verdict.');
		if (result.evidenceNote) lines.push(`> ${cell(result.evidenceNote)}`);
		else if (result.maturity && result.maturity !== 'Unknown') lines.push(`> ${cell(result.maturity)}`);
		lines.push('');
	}

	lines.push('| Metric | Value |');
	lines.push('|--------|-------|');
	lines.push(`| **Score** | ${result.measured ? `${result.score}/100` : 'not measured'} |`);
	lines.push(`| **Grade** | ${result.measured ? `**${result.grade}**` : 'not measured'} |`);
	lines.push(`| **Maturity** | ${cell(result.maturity)} |`);
	lines.push(`| **Scoring Profile** | ${cell(result.scoringProfile || requestedProfile)} |`);
	lines.push(`| **Minimum Grade** | ${minimumGrade} |`);
	lines.push(`| **Result** | ${passed ? '✅ Passed' : result.measured ? '❌ Failed' : '❔ Inconclusive'} |`);
	const counts = result.measured ? formatFindingCounts(result.findingCounts) : null;
	if (counts) lines.push(`| **Findings** | ${counts} |`);
	if (result.percentileRank != null) lines.push(`| **Percentile** | Top ${100 - result.percentileRank}% of ${cell(result.scoringProfile || 'scanned')} domains |`);
	if (result.spoofabilityScore != null) lines.push(`| **Spoofability** | ${result.spoofabilityScore}/100 (higher is worse) |`);
	if (result.cached) lines.push('| **Cached** | Yes — use `force-refresh: true` to re-scan |');
	if (result.reportUrl) lines.push(`| **Full report** | [${cell(result.reportUrl)}](${result.reportUrl}) |`);
	lines.push('');

	if (result.categories.length > 0) {
		lines.push('### Category Scores');
		lines.push('');
		lines.push('| Category | Score | Status |');
		lines.push('|----------|-------|--------|');
		for (const cat of result.categories) {
			const state = CATEGORY_STATE[cat.state] ?? CATEGORY_STATE.inconclusive;
			const score = cat.score == null ? state.label : `${cat.score}/100`;
			lines.push(`| ${cell(cat.name)} | ${score} | ${state.emoji} |`);
		}
		lines.push('');
	}

	if (result.findings.length > 0) {
		lines.push('### Top Findings');
		lines.push('');
		for (const finding of result.findings.slice(0, MAX_FINDINGS_IN_SUMMARY)) {
			const emoji = SEVERITY_EMOJI[finding.severity] ?? 'ℹ️';
			const category = finding.category ? ` \`${cell(finding.category)}\`` : '';
			lines.push(`- ${emoji} **[${finding.severity}]**${category} ${cell(finding.title)}`);
		}
		if (result.findings.length > MAX_FINDINGS_IN_SUMMARY) {
			lines.push(`- _...and ${result.findings.length - MAX_FINDINGS_IN_SUMMARY} more_`);
		}
		lines.push('');
	} else if (result.measured) {
		lines.push('### Findings');
		lines.push('');
		lines.push('✅ No security issues found.');
		lines.push('');
	}

	if (result.interactionEffects.length > 0) {
		lines.push('### Scoring Interactions');
		lines.push('');
		for (const effect of result.interactionEffects) {
			lines.push(`- **[-${effect.penalty}]** ${cell(effect.narrative)}`);
		}
		lines.push('');
	}

	lines.push('---');
	lines.push(`_Scanned by [Blackveil DNS Security Scanner](${repoUrl})_`);

	return lines.join('\n');
}
