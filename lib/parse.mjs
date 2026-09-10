/**
 * Normalise a `scan_domain` tool result into the shape the action reports on.
 *
 * Three sources are tried in order of reliability:
 *   1. `structuredContent` — the MCP-standard machine-readable channel (2025-06-18+).
 *   2. The legacy `<!-- STRUCTURED_RESULT ... -->` comment embedded in `content`.
 *   3. Regex over the human-readable text report (oldest servers / custom endpoints).
 *
 * Null semantics from the server contract (StructuredScanResult):
 *   - `score`/`grade` are null when the domain was NOT graded (NXDOMAIN, budget
 *     exceeded, too few checks completed). Null means "not measured", never "zero".
 *   - `categoryScores[cat]` is null when the category is not applicable to the
 *     domain or the check could not be measured; the two reasons are listed in
 *     `notApplicableCategories` and `inconclusiveCategories` respectively.
 */

export const STRUCTURED_COMMENT_RE = /<!-- STRUCTURED_RESULT\n([\s\S]*?)\nSTRUCTURED_RESULT -->/;

const EMPTY_COUNTS = Object.freeze({ critical: 0, high: 0, medium: 0, low: 0 });

function contentText(contentArray) {
	if (!Array.isArray(contentArray)) return typeof contentArray === 'string' ? contentArray : '';
	return contentArray
		.filter((item) => item && typeof item.text === 'string')
		.map((item) => item.text)
		.join('\n');
}

function categoryState(score, category, notApplicable, inconclusive) {
	if (inconclusive.includes(category)) return 'inconclusive';
	if (notApplicable.includes(category)) return 'not_applicable';
	if (typeof score !== 'number') return 'inconclusive';
	if (score >= 80) return 'ok';
	if (score >= 50) return 'warn';
	return 'fail';
}

function toFindingList(findings) {
	if (!Array.isArray(findings)) return [];
	return findings
		.filter((f) => f && typeof f.title === 'string' && typeof f.severity === 'string')
		.filter((f) => f.severity.toLowerCase() !== 'info')
		.map((f) => ({
			severity: f.severity.toUpperCase(),
			title: f.title,
			category: typeof f.category === 'string' ? f.category : null,
		}));
}

/** Shape a structured payload (from either channel) into the normalised result. */
function fromStructured(data, source, rawText) {
	const measured = typeof data.score === 'number' && typeof data.grade === 'string';
	const notApplicable = Array.isArray(data.notApplicableCategories) ? data.notApplicableCategories : [];
	const inconclusive = Array.isArray(data.inconclusiveCategories) ? data.inconclusiveCategories : [];
	const categoryScores = data.categoryScores && typeof data.categoryScores === 'object' ? data.categoryScores : {};

	const categories = Object.entries(categoryScores).map(([name, score]) => ({
		name: name.toUpperCase(),
		score: typeof score === 'number' ? score : null,
		state: categoryState(score, name, notApplicable, inconclusive),
	}));

	// Structured findings (server >= 3.x). Older structured blocks only carried
	// counts, so fall back to the text report for titles in that case.
	const findings = Array.isArray(data.findings) ? toFindingList(data.findings) : parseFindingsFromText(rawText);

	const counts = data.findingCounts && typeof data.findingCounts === 'object' ? data.findingCounts : null;

	return {
		source,
		measured,
		score: measured ? data.score : null,
		grade: measured ? data.grade : null,
		maturity: typeof data.maturityLabel === 'string' ? data.maturityLabel : 'Unknown',
		scoringProfile: typeof data.scoringProfile === 'string' ? data.scoringProfile : null,
		categories,
		findings,
		findingCounts: counts ? { ...EMPTY_COUNTS, ...counts } : null,
		interactionEffects: Array.isArray(data.interactionEffects) ? data.interactionEffects : [],
		percentileRank: typeof data.percentileRank === 'number' ? data.percentileRank : null,
		spoofabilityScore: typeof data.spoofabilityScore === 'number' ? data.spoofabilityScore : null,
		evidenceInsufficient: data.evidenceInsufficient === true,
		evidenceNote: typeof data.evidenceNote === 'string' ? data.evidenceNote : null,
		notApplicableCategories: notApplicable,
		inconclusiveCategories: inconclusive,
		cached: data.cached === true,
		reportUrl: typeof data.report_url === 'string' ? data.report_url : null,
		serverVersion: typeof data.dnsChecksPackageVersion === 'string' ? data.dnsChecksPackageVersion : null,
		rawText,
	};
}

/** Extract the legacy STRUCTURED_RESULT JSON from a content array, or null. */
export function extractLegacyStructuredBlock(contentArray) {
	if (!Array.isArray(contentArray)) return null;
	for (const item of contentArray) {
		const match = typeof item?.text === 'string' ? item.text.match(STRUCTURED_COMMENT_RE) : null;
		if (!match) continue;
		try {
			const data = JSON.parse(match[1]);
			if (data && typeof data === 'object') return data;
		} catch {
			// Malformed JSON — fall through to the next item / regex parsing.
		}
	}
	return null;
}

/** Findings from the text report: lines like `  [HIGH] Some finding title`. Info lines are dropped. */
export function parseFindingsFromText(text) {
	const findings = [];
	const pattern = /^\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)\s*$/gim;
	let match;
	while ((match = pattern.exec(text ?? '')) !== null) {
		const severity = match[1].toUpperCase();
		if (severity === 'INFO') continue;
		findings.push({ severity, title: match[2], category: null });
	}
	return findings;
}

/** Regex fallback over the human-readable report. */
export function parseScanResultFromText(text) {
	const source = 'text';
	const rawText = text ?? '';

	// "Overall Score: 82/100 (B)" or "Overall Score: not measured"
	const scoreMatch = rawText.match(/Overall Score:\s*(\d+)\/100\s*\(([^)]+)\)/);
	const measured = Boolean(scoreMatch);

	const maturityMatch = rawText.match(/Email Security Maturity:\s*(?:Stage\s*\d+|not measured)\s*[—–-]\s*(.+)/);
	const profileMatch = rawText.match(/Scoring Profile:\s*([a-z_]+)/i);

	const categories = [];
	const categoryPattern = /^\s*([✓⚠✗])\s+(\S+)\s+(\d+)\/100/gm;
	let catMatch;
	while ((catMatch = categoryPattern.exec(rawText)) !== null) {
		const score = parseInt(catMatch[3], 10);
		categories.push({
			name: catMatch[2].toUpperCase(),
			score,
			state: score >= 80 ? 'ok' : score >= 50 ? 'warn' : 'fail',
		});
	}

	const findings = parseFindingsFromText(rawText);
	const findingCounts = findings.reduce(
		(acc, f) => {
			const key = f.severity.toLowerCase();
			if (key in acc) acc[key] += 1;
			return acc;
		},
		{ ...EMPTY_COUNTS },
	);

	return {
		source,
		measured,
		score: measured ? parseInt(scoreMatch[1], 10) : null,
		grade: measured ? scoreMatch[2].trim() : null,
		maturity: maturityMatch ? maturityMatch[1].trim() : 'Unknown',
		scoringProfile: profileMatch ? profileMatch[1].toLowerCase() : null,
		categories,
		findings,
		findingCounts,
		interactionEffects: [],
		percentileRank: null,
		spoofabilityScore: null,
		evidenceInsufficient: false,
		evidenceNote: null,
		notApplicableCategories: [],
		inconclusiveCategories: [],
		cached: false,
		reportUrl: null,
		serverVersion: null,
		rawText,
	};
}

/**
 * Parse a `tools/call` result object (`{ content, structuredContent?, isError? }`).
 */
export function parseScanResult(toolResult) {
	const content = toolResult?.content;
	const rawText = contentText(content);

	const sc = toolResult?.structuredContent;
	if (sc && typeof sc === 'object' && 'score' in sc && 'grade' in sc) {
		return fromStructured(sc, 'structured_content', rawText);
	}

	const legacy = extractLegacyStructuredBlock(content);
	if (legacy && 'score' in legacy && 'grade' in legacy) {
		return fromStructured(legacy, 'legacy_comment', rawText);
	}

	return parseScanResultFromText(rawText);
}
