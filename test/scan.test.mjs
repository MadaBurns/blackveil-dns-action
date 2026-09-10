import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readInputs, evaluate, normalizeDomain, VALID_PROFILES } from '../scan.mjs';
import { parseScanResult } from '../lib/parse.mjs';
import { buildSummaryMarkdown } from '../lib/summary.mjs';
import { setOutput } from '../lib/github.mjs';
import { loadFixture } from './helpers.mjs';

const base = { INPUT_DOMAIN: 'Example.COM.' };

test('readInputs applies defaults and normalises', () => {
	const i = readInputs(base);
	assert.equal(i.domain, 'example.com');
	assert.equal(i.minimumGrade, 'C');
	assert.equal(i.profile, 'auto');
	assert.equal(i.forceRefresh, false);
	assert.equal(i.failOnInconclusive, true);
	assert.match(i.endpoint, /^https:\/\//);
});

test('readInputs rejects bad domain, profile, endpoint and booleans', () => {
	assert.throws(() => readInputs({}), /Missing required input: domain/);
	assert.throws(() => readInputs({ INPUT_DOMAIN: 'https://example.com' }), /bare hostname/);
	assert.throws(() => readInputs({ INPUT_DOMAIN: 'localhost' }), /bare hostname/);
	assert.throws(() => readInputs({ ...base, INPUT_PROFILE: 'bogus' }), /Invalid profile/);
	assert.throws(() => readInputs({ ...base, INPUT_ENDPOINT: 'http://insecure.test/mcp' }), /https:\/\//);
	assert.throws(() => readInputs({ ...base, INPUT_FORCE_REFRESH: 'maybe' }), /Expected a boolean/);
	assert.ok(VALID_PROFILES.includes('authoritative_dns_infra'));
	assert.equal(normalizeDomain('  Sub.Example.org '), 'sub.example.org');
});

test('evaluate: pass, fail and inconclusive verdicts', () => {
	const ok = parseScanResult(loadFixture('cloudflare'));
	assert.deepEqual(evaluate(ok, { domain: 'cloudflare.com', minimumGrade: 'A', failOnInconclusive: true }), {
		passed: true,
		exitCode: 0,
		message: null,
		level: null,
	});

	const low = { ...ok, grade: 'D', score: 61 };
	const fail = evaluate(low, { domain: 'x.com', minimumGrade: 'C', failOnInconclusive: true });
	assert.equal(fail.passed, false);
	assert.equal(fail.exitCode, 1);
	assert.match(fail.message, /grade D \(61\/100\) is below minimum C/);

	const nx = parseScanResult(loadFixture('nxdomain'));
	const strict = evaluate(nx, { domain: 'nx.com', minimumGrade: 'F', failOnInconclusive: true });
	assert.equal(strict.passed, false);
	assert.equal(strict.exitCode, 1);
	assert.match(strict.message, /could not be graded: Does not resolve/);

	const lenient = evaluate(nx, { domain: 'nx.com', minimumGrade: 'F', failOnInconclusive: false });
	assert.equal(lenient.passed, false);
	assert.equal(lenient.exitCode, 0);
	assert.equal(lenient.level, 'warning');
});

test('summary renders a graded scan with categories, findings and report link', () => {
	const r = parseScanResult(loadFixture('cloudflare'));
	const md = buildSummaryMarkdown(r, { domain: 'cloudflare.com', minimumGrade: 'B', passed: true, requestedProfile: 'auto', repoUrl: 'https://repo' });
	assert.match(md, /Blackveil DNS Security Scan: `cloudflare.com`/);
	assert.match(md, /\| \*\*Score\*\* \| 95\/100 \|/);
	assert.match(md, /\| \*\*Grade\*\* \| \*\*A\+\*\* \|/);
	assert.match(md, /✅ Passed/);
	assert.match(md, /security-report\/cloudflare\.com/);
	assert.match(md, /### Category Scores/);
	assert.match(md, /\| SPF \| 85\/100 \| ✅ \|/);
	assert.match(md, /### Top Findings/);
	assert.match(md, /\*\*\[MEDIUM\]\*\* `spf` TXT RRset exceeds UDP limit/);
	assert.doesNotMatch(md, /null/);
});

test('summary renders an ungraded scan honestly', () => {
	const r = parseScanResult(loadFixture('nxdomain'));
	const md = buildSummaryMarkdown(r, { domain: 'nx.com', minimumGrade: 'C', passed: false, requestedProfile: 'auto', repoUrl: 'https://repo' });
	assert.match(md, /\*\*Not measured\.\*\*/);
	assert.match(md, /\| \*\*Score\*\* \| not measured \|/);
	assert.match(md, /❔ Inconclusive/);
	assert.doesNotMatch(md, /No security issues found/);
	assert.doesNotMatch(md, /null/);
});

test('summary shows N/A and Inconclusive categories instead of null/100', () => {
	const fx = loadFixture('cloudflare');
	fx.structuredContent.categoryScores = { spf: 85, bimi: null, dane: null };
	fx.structuredContent.notApplicableCategories = ['bimi'];
	fx.structuredContent.inconclusiveCategories = ['dane'];
	const md = buildSummaryMarkdown(parseScanResult(fx), { domain: 'x', minimumGrade: 'C', passed: true, requestedProfile: 'auto', repoUrl: 'u' });
	assert.match(md, /\| BIMI \| N\/A \| ➖ \|/);
	assert.match(md, /\| DANE \| Inconclusive \| ❔ \|/);
	assert.doesNotMatch(md, /null\/100/);
});

test('summary escapes pipes and newlines in server-supplied text', () => {
	const fx = loadFixture('cloudflare');
	fx.structuredContent.findings = [{ category: 'spf', severity: 'high', title: 'a | b\nc', detail: '' }];
	const md = buildSummaryMarkdown(parseScanResult(fx), { domain: 'x', minimumGrade: 'C', passed: true, requestedProfile: 'auto', repoUrl: 'u' });
	assert.match(md, /a \\\| b c/);
});

test('setOutput writes heredoc-delimited values to GITHUB_OUTPUT', () => {
	const dir = mkdtempSync(join(tmpdir(), 'bvdns-'));
	const file = join(dir, 'out');
	setOutput('grade', 'A+', { GITHUB_OUTPUT: file });
	setOutput('note', 'line1\nline2=x', { GITHUB_OUTPUT: file });
	setOutput('empty', null, { GITHUB_OUTPUT: file });
	const text = readFileSync(file, 'utf8');
	assert.match(text, /^grade<<ghadelimiter_[0-9a-f]{16}\nA\+\nghadelimiter_[0-9a-f]{16}\n/);
	assert.match(text, /note<<ghadelimiter_[0-9a-f]{16}\nline1\nline2=x\nghadelimiter_/);
	assert.match(text, /empty<<ghadelimiter_[0-9a-f]{16}\n\nghadelimiter_/);
});
