import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseScanResult, parseFindingsFromText, extractLegacyStructuredBlock } from '../lib/parse.mjs';
import { loadFixture, withoutStructuredContent, textOnly } from './helpers.mjs';

test('prefers structuredContent and reads every reported field', () => {
	const r = parseScanResult(loadFixture('cloudflare'));
	assert.equal(r.source, 'structured_content');
	assert.equal(r.measured, true);
	assert.equal(r.score, 95);
	assert.equal(r.grade, 'A+');
	assert.equal(r.maturity, 'Hardened');
	assert.equal(r.scoringProfile, 'mail_enabled');
	assert.equal(r.reportUrl, 'https://www.blackveilsecurity.com/security-report/cloudflare.com');
	assert.equal(r.cached, false);
	assert.deepEqual(Object.keys(r.findingCounts), ['critical', 'high', 'medium', 'low']);
	assert.ok(r.categories.length >= 15);
	const spf = r.categories.find((c) => c.name === 'SPF');
	assert.deepEqual(spf, { name: 'SPF', score: 85, state: 'ok' });
	const dkim = r.categories.find((c) => c.name === 'DKIM');
	assert.equal(dkim.state, 'warn');
});

test('structured findings drop info-level entries and keep category', () => {
	const r = parseScanResult(loadFixture('cloudflare'));
	assert.ok(r.findings.length > 0);
	assert.ok(r.findings.every((f) => f.severity !== 'INFO'));
	assert.ok(r.findings.every((f) => typeof f.category === 'string'));
	assert.equal(r.findings[0].title, 'TXT RRset exceeds UDP limit');
	assert.equal(r.findings[0].severity, 'MEDIUM');
});

test('falls back to the legacy STRUCTURED_RESULT comment', () => {
	const r = parseScanResult(withoutStructuredContent(loadFixture('cloudflare')));
	assert.equal(r.source, 'legacy_comment');
	assert.equal(r.score, 95);
	assert.equal(r.grade, 'A+');
	assert.ok(r.findings.length > 0);
});

test('falls back to regex over the text report', () => {
	const r = parseScanResult(textOnly(loadFixture('cloudflare')));
	assert.equal(r.source, 'text');
	assert.equal(r.measured, true);
	assert.equal(r.score, 95);
	assert.equal(r.grade, 'A+');
	assert.equal(r.maturity, 'Hardened');
	assert.equal(r.scoringProfile, 'mail_enabled');
	assert.ok(r.categories.some((c) => c.name === 'DNSSEC' && c.score === 100 && c.state === 'ok'));
	assert.ok(r.findings.some((f) => f.severity === 'HIGH'));
	assert.equal(r.findingCounts.high, 1);
});

test('an ungraded domain is reported as not measured, never as grade null', () => {
	for (const shape of [loadFixture('nxdomain'), withoutStructuredContent(loadFixture('nxdomain')), textOnly(loadFixture('nxdomain'))]) {
		const r = parseScanResult(shape);
		assert.equal(r.measured, false, `source=${r.source}`);
		assert.equal(r.score, null);
		assert.equal(r.grade, null);
		assert.equal(r.findings.length, 0);
	}
	const structured = parseScanResult(loadFixture('nxdomain'));
	assert.equal(structured.maturity, 'Does not resolve');
});

test('null category scores are classified as not applicable or inconclusive', () => {
	const fx = loadFixture('cloudflare');
	fx.structuredContent.categoryScores = { spf: 85, bimi: null, dane: null, ptr: null };
	fx.structuredContent.notApplicableCategories = ['bimi'];
	fx.structuredContent.inconclusiveCategories = ['dane'];
	const r = parseScanResult(fx);
	const byName = Object.fromEntries(r.categories.map((c) => [c.name, c]));
	assert.equal(byName.SPF.state, 'ok');
	assert.deepEqual(byName.BIMI, { name: 'BIMI', score: null, state: 'not_applicable' });
	assert.deepEqual(byName.DANE, { name: 'DANE', score: null, state: 'inconclusive' });
	// null with no explanation is treated as inconclusive, not as a 0/100 failure
	assert.equal(byName.PTR.state, 'inconclusive');
});

test('structured block without findings array falls back to text findings', () => {
	const fx = withoutStructuredContent(loadFixture('cloudflare'));
	const idx = fx.content.findIndex((c) => c.text.startsWith('<!-- STRUCTURED_RESULT'));
	const data = extractLegacyStructuredBlock(fx.content);
	delete data.findings;
	fx.content[idx].text = `<!-- STRUCTURED_RESULT\n${JSON.stringify(data)}\nSTRUCTURED_RESULT -->`;
	const r = parseScanResult(fx);
	assert.equal(r.source, 'legacy_comment');
	assert.ok(r.findings.length > 0);
	assert.equal(r.findings[0].category, null);
});

test('malformed legacy JSON falls through to text parsing', () => {
	const fx = withoutStructuredContent(loadFixture('cloudflare'));
	const idx = fx.content.findIndex((c) => c.text.startsWith('<!-- STRUCTURED_RESULT'));
	fx.content[idx].text = '<!-- STRUCTURED_RESULT\n{not json\nSTRUCTURED_RESULT -->';
	const r = parseScanResult(fx);
	assert.equal(r.source, 'text');
	assert.equal(r.score, 95);
});

test('parseFindingsFromText only matches severity tags at line start', () => {
	const text = [
		'  [HIGH] Real finding',
		'  [INFO] Ignored info',
		'    Detail mentions [SPF] in brackets and [FOO] too',
		'[low] lowercase tag',
	].join('\n');
	assert.deepEqual(
		parseFindingsFromText(text).map((f) => `${f.severity}|${f.title}`),
		['HIGH|Real finding', 'LOW|lowercase tag'],
	);
});

test('tolerates garbage input', () => {
	assert.equal(parseScanResult(null).measured, false);
	assert.equal(parseScanResult({}).measured, false);
	assert.equal(parseScanResult({ content: 'plain string' }).measured, false);
	assert.equal(parseScanResult({ content: [{ type: 'image' }] }).measured, false);
});
