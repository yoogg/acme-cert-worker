import type { ZoneMapEntry } from "./env";

export type CloudflareDnsRecord = {
	id: string;
	name: string;
	content: string;
	ttl: number;
	type: string;
};

export type CreatedTxtRecord = {
	record: CloudflareDnsRecord;
	created: boolean;
};

export function findZoneIdForDomain(domain: string, zoneMap: ZoneMapEntry[]): string | null {
	const d = domain.toLowerCase().replace(/^\*\./, "");
	let best: ZoneMapEntry | null = null;
	for (const entry of zoneMap) {
		const suffix = entry.suffix.toLowerCase();
		if (d === suffix || d.endsWith(`.${suffix}`)) {
			if (!best || suffix.length > best.suffix.length) best = entry;
		}
	}
	return best?.zoneId ?? null;
}

export async function resolveZoneIdForDomain(cfApiToken: string, domain: string, zoneMap: ZoneMapEntry[]): Promise<string> {
	const mapped = findZoneIdForDomain(domain, zoneMap);
	if (mapped) return mapped;

	// Fallback: query Cloudflare Zones API by walking up the domain labels.
	// Requires the API token to have Zone:Read in addition to DNS Edit.
	let candidate = domain.toLowerCase().replace(/^\*\./, "");
	while (candidate.includes(".")) {
		const zoneId = await tryGetZoneIdByName(cfApiToken, candidate);
		if (zoneId) return zoneId;
		candidate = candidate.split(".").slice(1).join(".");
	}
	throw new Error(
		"Missing/invalid CF_ZONE_MAP_JSON (and auto zone lookup failed). " +
			"Either set CF_ZONE_MAP_JSON with zoneId mapping, or grant the token Zone:Read and retry.",
	);
}

async function tryGetZoneIdByName(cfApiToken: string, zoneName: string): Promise<string | null> {
	const url = new URL("https://api.cloudflare.com/client/v4/zones");
	url.searchParams.set("name", zoneName);
	url.searchParams.set("status", "active");
	url.searchParams.set("per_page", "1");
	const res = await fetch(url.toString(), {
		headers: {
			authorization: `Bearer ${cfApiToken}`,
			accept: "application/json",
		},
	});
	const body = (await res.json()) as any;
	if (!res.ok || body?.success === false) {
		return null;
	}
	const first = body?.result?.[0];
	return typeof first?.id === "string" ? first.id : null;
}

export function dns01RecordName(domainOrWildcard: string): string {
	const d = domainOrWildcard.toLowerCase().replace(/^\*\./, "");
	return `_acme-challenge.${d}`;
}

export async function createTxtRecord(cfApiToken: string, zoneId: string, name: string, content: string): Promise<CreatedTxtRecord> {
	// 幂等：如果已存在相同的 TXT（常见于上次异常未清理、或并发请求），直接复用
	const existing = await findExistingTxtRecord(cfApiToken, zoneId, name, content);
	if (existing) return { record: existing, created: false };

	const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${cfApiToken}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ type: "TXT", name, content, ttl: 60 }),
	});
	const body = (await res.json()) as any;
	if (!res.ok || body?.success === false) {
		// 81058: An identical record already exists.
		const errorCodes: number[] = Array.isArray(body?.errors) ? body.errors.map((e: any) => e?.code).filter((x: any) => typeof x === "number") : [];
		if (errorCodes.includes(81058)) {
			const found = await findExistingTxtRecord(cfApiToken, zoneId, name, content);
			if (found) return { record: found, created: false };
		}
		throw new Error(`Cloudflare DNS create failed: ${res.status} ${JSON.stringify(body).slice(0, 2000)}`);
	}
	return { record: body.result as CloudflareDnsRecord, created: true };
}

async function findExistingTxtRecord(
	cfApiToken: string,
	zoneId: string,
	name: string,
	content: string,
): Promise<CloudflareDnsRecord | null>
{
	const url = new URL(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`);
	url.searchParams.set("type", "TXT");
	url.searchParams.set("name", name);
	url.searchParams.set("per_page", "100");
	const res = await fetch(url.toString(), {
		headers: {
			authorization: `Bearer ${cfApiToken}`,
			accept: "application/json",
		},
	});
	if (!res.ok) return null;
	const body = (await res.json()) as any;
	if (body?.success === false || !Array.isArray(body?.result)) return null;
	const found = (body.result as any[]).find((r) => r?.type === "TXT" && r?.name === name && r?.content === content);
	return found && typeof found.id === "string" ? (found as CloudflareDnsRecord) : null;
}

export async function deleteRecord(cfApiToken: string, zoneId: string, recordId: string): Promise<void> {
	const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${recordId}`, {
		method: "DELETE",
		headers: {
			authorization: `Bearer ${cfApiToken}`,
		},
	});
	if (!res.ok) {
		const text = await res.text();
		throw new Error(`Cloudflare DNS delete failed: ${res.status} ${text.slice(0, 1000)}`);
	}
}
