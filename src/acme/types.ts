export type AcmeDirectory = {
	newNonce: string;
	newAccount: string;
	newOrder: string;
	revokeCert?: string;
	keyChange?: string;
	meta?: {
		termsOfService?: string;
	};
};

export type AcmeOrder = {
	status: "pending" | "ready" | "processing" | "valid" | "invalid";
	authorizations: string[];
	finalize: string;
	certificate?: string;
	expires?: string;
};

export type AcmeAuthorization = {
	identifier: { type: "dns"; value: string };
	status: "pending" | "valid" | "invalid" | "deactivated" | "expired" | "revoked";
	challenges: Array<{
		type: string;
		url: string;
		status: string;
		token: string;
		error?: unknown;
	}>;
};
