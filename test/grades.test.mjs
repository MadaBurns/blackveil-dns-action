import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GRADE_ORDER, gradeRank, meetsMinimumGrade, normalizeMinimumGrade } from '../lib/grades.mjs';

test('grade order is the NIST 6-band display scale', () => {
	assert.deepEqual([...GRADE_ORDER], ['A+', 'A', 'B', 'C', 'D', 'F']);
});

test('meetsMinimumGrade compares by band', () => {
	assert.equal(meetsMinimumGrade('A+', 'C'), true);
	assert.equal(meetsMinimumGrade('C', 'C'), true);
	assert.equal(meetsMinimumGrade('D', 'C'), false);
	assert.equal(meetsMinimumGrade('F', 'F'), true);
});

test('a null or unknown grade never passes', () => {
	assert.equal(meetsMinimumGrade(null, 'F'), false);
	assert.equal(meetsMinimumGrade(undefined, 'F'), false);
	assert.equal(meetsMinimumGrade('Z', 'F'), false);
	assert.equal(gradeRank('Z'), GRADE_ORDER.length);
});

test('normalizeMinimumGrade accepts current bands case-insensitively and defaults to C', () => {
	assert.deepEqual(normalizeMinimumGrade(' b '), { grade: 'B', warning: null });
	assert.deepEqual(normalizeMinimumGrade('a+'), { grade: 'A+', warning: null });
	assert.deepEqual(normalizeMinimumGrade(''), { grade: 'C', warning: null });
	assert.deepEqual(normalizeMinimumGrade(undefined), { grade: 'C', warning: null });
});

test('normalizeMinimumGrade maps legacy 9-band inputs with a warning', () => {
	const r = normalizeMinimumGrade('B+');
	assert.equal(r.grade, 'B');
	assert.match(r.warning, /legacy 9-band/);
	assert.equal(normalizeMinimumGrade('c+').grade, 'C');
	assert.equal(normalizeMinimumGrade('D+').grade, 'D');
});

test('normalizeMinimumGrade rejects unknown grades', () => {
	assert.throws(() => normalizeMinimumGrade('E'), /Invalid minimum-grade/);
	assert.throws(() => normalizeMinimumGrade('A++'), /Invalid minimum-grade/);
});
