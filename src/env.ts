export type CaProviderConfig = {
	provider: string;
	directoryUrl: string;
	eab?: {
		kid: string;
		hmacKeyBase64url: string;
	};
};

export type Env = {
	CERTS_KV: KVNamespace;

	ALLOWED_DOMAINS: string;
	AUTH_TOKEN: string;

	CF_API_TOKEN: string;
	CF_ZONE_MAP_JSON: string;

	RENEW_BEFORE_DAYS: string;
	DNS_PROPAGATION_SECONDS: string;

	CA_PROVIDERS_JSON: string;
};

export function parseIntEnv(value: string | undefined, fallback: number): number {
	const parsed = Number.parseInt(value ?? "", 10);
	return Number.isFinite(parsed) ? parsed : fallback;
}

export function parseAllowedDomains(value: string): string[] {
	return value
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}

export function parseCaProviders(json: string): CaProviderConfig[] {
	try {
		const parsed = JSON.parse(json) as unknown;
		if (!Array.isArray(parsed)) return [];
		return parsed
			.map((x) => x as CaProviderConfig)
			.filter((x) => typeof x?.directoryUrl === "string" && x.directoryUrl.length > 0);
	} catch {
		return [];
	}
}

export type ZoneMapEntry = { suffix: string; zoneId: string };

export function parseZoneMap(json: string): ZoneMapEntry[] {
	try {
		const parsed = JSON.parse(json) as unknown;
		if (!Array.isArray(parsed)) return [];
		return parsed
			.map((x) => x as ZoneMapEntry)
			.filter((x) => typeof x?.suffix === "string" && typeof x?.zoneId === "string")
			.map((x) => ({ suffix: x.suffix.toLowerCase(), zoneId: x.zoneId }));
	} catch {
		return [];
	}
}
