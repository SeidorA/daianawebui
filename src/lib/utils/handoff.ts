export type HandoffUrlState = {
	token: string | null;
	cleanupUrl: string;
};

export const getHandoffTokenFromUrl = (url: string | URL): string | null => {
	const parsedUrl = new URL(url);
	const fragmentParams = new URLSearchParams(parsedUrl.hash.replace(/^#/, ''));

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
