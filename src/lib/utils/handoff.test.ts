import { describe, expect, it } from 'vitest';

import { getHandoffCleanupUrl, getHandoffTokenFromUrl, parseHandoffUrl } from './handoff';

describe('handoff URL helpers', () => {
	it('prefers fragment handoff token over legacy query token', () => {
		const url = 'https://example.test/auth?handoff=query-token#handoff=fragment-token';

		expect(getHandoffTokenFromUrl(url)).toBe('fragment-token');
	});

	it('falls back to legacy query handoff token', () => {
		const url = 'https://example.test/auth?handoff=query-token';

		expect(getHandoffTokenFromUrl(url)).toBe('query-token');
	});

	it('preserves non-secret redirect and returnTo query params during cleanup', () => {
		const url =
			'https://example.test/auth?handoff=query-token&redirect=%2Fchat&returnTo=https%3A%2F%2Fapp.example.test%2Fdone#handoff=fragment-token';

		expect(getHandoffCleanupUrl(url)).toBe(
			'/auth?redirect=%2Fchat&returnTo=https%3A%2F%2Fapp.example.test%2Fdone'
		);
	});

	it('removes handoff token from query and fragment cleanup URL', () => {
		const url = 'https://example.test/auth?handoff=query-token&redirect=%2Fchat#handoff=fragment-token';
		const result = parseHandoffUrl(url);

		expect(result.token).toBe('fragment-token');
		expect(result.cleanupUrl).toBe('/auth?redirect=%2Fchat');
		expect(result.cleanupUrl).not.toContain('query-token');
		expect(result.cleanupUrl).not.toContain('fragment-token');
		expect(result.cleanupUrl).not.toContain('handoff');
		expect(result.cleanupUrl).not.toContain('#');
	});
});
