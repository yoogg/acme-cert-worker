import type { ZoneMapEntry } from "./env";

export type CloudflareDnsRecord = {
	id: string;
	name: string;
	content: string;
	ttl: number;
	type: string;
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

export function dns01RecordName(domainOrWildcard: string): string {
	const d = domainOrWildcard.toLowerCase().replace(/^\*\./, "");
	return `_acme-challenge.${d}`;
}

export async function createTxtRecord(cfApiToken: string, zoneId: string, name: string, content: string): Promise<CloudflareDnsRecord> {
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
		throw new Error(`Cloudflare DNS create failed: ${res.status} ${JSON.stringify(body).slice(0, 2000)}`);
	}
	return body.result as CloudflareDnsRecord;
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
