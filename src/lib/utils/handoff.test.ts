import { describe, expect, it } from 'vitest';

import {
	getHandoffCleanupUrl,
	getHandoffTokenFromUrl,
	isSafeReturnTo,
	parseAllowedReturnToOrigins,
	parseHandoffUrl
} from './handoff';

describe('handoff URL helpers', () => {
	it('prefers fragment handoff token over legacy query token', () => {
		const url = 'https://example.test/auth?handoff=query-token#handoff=fragment-token';

		expect(getHandoffTokenFromUrl(url)).toBe('fragment-token');
	});

	it('falls back to legacy query handoff token for compatibility', () => {
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

describe('handoff returnTo safety', () => {
	const baseOrigin = 'https://webui.example.test';

	it('allows same-origin absolute and safe relative return URLs', () => {
		expect(isSafeReturnTo('https://webui.example.test/done', baseOrigin)).toBe(true);
		expect(isSafeReturnTo('/done?ok=true', baseOrigin)).toBe(true);
		expect(isSafeReturnTo('settings/profile', baseOrigin)).toBe(true);
	});

	it('rejects arbitrary cross-origin http URLs by default', () => {
		expect(isSafeReturnTo('https://evil.example.test/done', baseOrigin)).toBe(false);
		expect(isSafeReturnTo('//evil.example.test/done', baseOrigin)).toBe(false);
	});

	it('allows cross-origin return URLs only when their origins are explicitly allowlisted', () => {
		expect(
			isSafeReturnTo('https://app.example.test/done', baseOrigin, ['https://app.example.test'])
		).toBe(true);
		expect(
			isSafeReturnTo('https://app.example.test.evil/done', baseOrigin, ['https://app.example.test'])
		).toBe(false);
	});

	it('covers the auth route returnTo redirect contract inputs', () => {
		const allowedOrigins = parseAllowedReturnToOrigins('https://app.example.test/callback');

		expect(isSafeReturnTo('/chat', baseOrigin, allowedOrigins)).toBe(true);
		expect(isSafeReturnTo('https://app.example.test/done', baseOrigin, allowedOrigins)).toBe(true);
		expect(isSafeReturnTo('https://evil.example.test/done', baseOrigin, allowedOrigins)).toBe(false);
	});

	it('normalizes configured allowlist values to origins', () => {
		const allowedOrigins = parseAllowedReturnToOrigins('https://app.example.test/callback, not-a-url');

		expect(isSafeReturnTo('https://app.example.test/done', baseOrigin, allowedOrigins)).toBe(true);
		expect(allowedOrigins).not.toContain('not-a-url');
	});

	it('rejects non-http protocols and malformed URLs', () => {
		expect(isSafeReturnTo('javascript:alert(1)', baseOrigin)).toBe(false);
		expect(isSafeReturnTo('data:text/html,hello', baseOrigin)).toBe(false);
		expect(isSafeReturnTo('http://[invalid', baseOrigin)).toBe(false);
	});
});
