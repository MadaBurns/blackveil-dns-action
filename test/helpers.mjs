import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

/** Load a captured `tools/call` result fixture (deep-cloned per call). */
export function loadFixture(name) {
	return JSON.parse(readFileSync(join(here, 'fixtures', `${name}.json`), 'utf8'));
}

/** The fixture with the MCP-standard `structuredContent` channel removed (legacy servers). */
export function withoutStructuredContent(result) {
	const { structuredContent, ...rest } = result;
	return rest;
}

/** The fixture reduced to the human-readable text report only (oldest servers). */
export function textOnly(result) {
	return {
		content: result.content.filter((c) => !c.text.trimStart().startsWith('<!-- STRUCTURED_RESULT')),
	};
}
