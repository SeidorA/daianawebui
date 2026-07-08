export type HandoffUrlState = {
	token: string | null;
	cleanupUrl: string;
};

export const parseAllowedReturnToOrigins = (value: string | undefined): string[] =>
	(value ?? '')
		.split(',')
		.map((origin) => origin.trim())
		.filter(Boolean)
		.flatMap((origin) => {
			try {
				const parsedOrigin = new URL(origin).origin;
				return parsedOrigin === 'null' ? [] : [parsedOrigin];
			} catch {
				return [];
			}
		});

export const isSafeReturnTo = (
	returnTo: string,
	baseOrigin: string,
	allowedOrigins: string[] = []
): boolean => {
	try {
		const url = new URL(returnTo, baseOrigin);
		const baseUrl = new URL(baseOrigin);

		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			return false;
		}

		return url.origin === baseUrl.origin || allowedOrigins.includes(url.origin);
	} catch {
		return false;
	}
};

export const getHandoffTokenFromUrl = (url: string | URL): string | null => {
	const parsedUrl = new URL(url);
	const fragmentParams = new URLSearchParams(parsedUrl.hash.replace(/^#/, ''));

	// Legacy compatibility: older handoff links used the query string. Prefer fragments
	// because they avoid sending the token to the server in the request URL.
	return fragmentParams.get('handoff') || parsedUrl.searchParams.get('handoff');
};

export const getHandoffCleanupUrl = (url: string | URL): string => {
	const parsedUrl = new URL(url);
	parsedUrl.searchParams.delete('handoff');
	parsedUrl.hash = '';

	return `${parsedUrl.pathname}${parsedUrl.search}`;
};

export const parseHandoffUrl = (url: string | URL): HandoffUrlState => ({
	token: getHandoffTokenFromUrl(url),
	cleanupUrl: getHandoffCleanupUrl(url)
});
