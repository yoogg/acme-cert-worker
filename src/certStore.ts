import * as x509 from "@peculiar/x509";
import { extractFirstCertificatePem } from "./utils/pem";

export type CachedCert = {
	domain: string;
	certPem: string;
	keyPem: string;
	notAfterIso: string;
	provider: string;
	updatedAtIso: string;
};

export async function loadCachedCert(kv: KVNamespace, domain: string): Promise<CachedCert | null> {
	const raw = await kv.get(certKey(domain));
	if (!raw) return null;
	try {
		return JSON.parse(raw) as CachedCert;
	} catch {
		return null;
	}
}

export async function saveCachedCert(kv: KVNamespace, cert: CachedCert): Promise<void> {
	await kv.put(certKey(cert.domain), JSON.stringify(cert));
}

export function parseNotAfterFromPemChain(pemChain: string): Date {
	const first = extractFirstCertificatePem(pemChain);
	const cert = new x509.X509Certificate(first);
	return cert.notAfter;
}

export function daysUntil(date: Date, now = new Date()): number {
	return Math.floor((date.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
}

function certKey(domain: string): string {
	return `cert:${domain.toLowerCase()}`;
}
