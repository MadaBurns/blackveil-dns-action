/**
 * Grade scale and threshold comparison.
 *
 * The Blackveil DNS server emits the NIST-aligned 6-band DISPLAY grade
 * (A+, A, B, C, D, F — thresholds 95/90/80/70/60). Earlier server versions
 * emitted a 9-band scale with B+/C+/D+; those inputs are still accepted for
 * backwards compatibility and are mapped to the nearest band the server can
 * actually emit, with a warning.
 */

export const GRADE_ORDER = Object.freeze(['A+', 'A', 'B', 'C', 'D', 'F']);

/** Legacy 9-band inputs that the server no longer emits, mapped to their base band. */
export const LEGACY_GRADE_ALIASES = Object.freeze({ 'B+': 'B', 'C+': 'C', 'D+': 'D' });

/** Score thresholds of the display scale — for documentation and the summary only. */
export const GRADE_THRESHOLDS = Object.freeze({ 'A+': 95, A: 90, B: 80, C: 70, D: 60, F: 0 });

/**
 * Rank of a grade in GRADE_ORDER; lower is better. Unknown or null grades rank
 * below F so they never satisfy any threshold.
 */
export function gradeRank(grade) {
	const index = GRADE_ORDER.indexOf(grade);
	return index === -1 ? GRADE_ORDER.length : index;
}

/**
 * Normalise the `minimum-grade` input.
 *
 * @returns {{ grade: string, warning: string | null }}
 * @throws {Error} when the input is not a recognised grade.
 */
export function normalizeMinimumGrade(input) {
	const raw = String(input ?? '').trim().toUpperCase();
	const value = raw === '' ? 'C' : raw;
	if (GRADE_ORDER.includes(value)) {
		return { grade: value, warning: null };
	}
	const alias = LEGACY_GRADE_ALIASES[value];
	if (alias) {
		return {
			grade: alias,
			warning:
				`minimum-grade "${value}" belongs to the legacy 9-band scale; the server now reports ` +
				`${GRADE_ORDER.join(', ')}. Treating it as "${alias}" (score >= ${GRADE_THRESHOLDS[alias]}).`,
		};
	}
	throw new Error(
		`Invalid minimum-grade: "${value}". Must be one of: ${GRADE_ORDER.join(', ')} ` +
			`(legacy ${Object.keys(LEGACY_GRADE_ALIASES).join(', ')} are also accepted).`,
	);
}

/**
 * Whether an emitted grade satisfies the minimum. A null/unknown grade never
 * passes — an ungraded scan is not evidence of a secure domain.
 */
export function meetsMinimumGrade(actual, minimum) {
	if (typeof actual !== 'string') return false;
	return gradeRank(actual) <= gradeRank(minimum);
}
