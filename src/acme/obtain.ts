import { AcmeClient, type AcmeProviderConfig } from "./client";
import { loadAccount, saveAccount } from "./accountStore";
import { generateCsrDer, generateTlsKeyPair, exportPrivateKeyPem } from "../csr";
import { generateEcP256KeyPair, exportJwkPrivate, exportJwkPublic } from "../utils/webcrypto";
import { createTxtRecord, deleteRecord, dns01RecordName, resolveZoneIdForDomain } from "../cloudflareDns";
import type { ZoneMapEntry } from "../env";

export type ObtainedCertificate = {
	certPem: string;
	keyPem: string;
	notAfter: Date;
	provider: string;
};

export async function obtainCertificateWithFallback(params: {
	providers: AcmeProviderConfig[];
	kv: KVNamespace;
	domain: string;
	includeApexWithWildcard: boolean;
	cfApiToken: string;
	zoneMap: ZoneMapEntry[];
	dnsPropagationSeconds: number;
	acmeContactEmail?: string;
	log: (msg: string) => void;
}): Promise<ObtainedCertificate>
{
	const errors: string[] = [];
	for (const provider of params.providers) {
		try {
			params.log(`ACME provider start: ${provider.provider} ${provider.directoryUrl}`);
			const cert = await obtainCertificateSingle({ ...params, provider });
			params.log(`ACME provider success: ${provider.provider}`);
			return cert;
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			params.log(`ACME provider failed: ${provider.provider}: ${msg}`);
			errors.push(`${provider.provider}: ${msg}`);
		}
	}
	throw new Error(`All ACME providers failed: ${errors.join(" | ")}`);
}

async function obtainCertificateSingle(params: {
	provider: AcmeProviderConfig;
	kv: KVNamespace;
	domain: string;
	includeApexWithWildcard: boolean;
	cfApiToken: string;
	zoneMap: ZoneMapEntry[];
	dnsPropagationSeconds: number;
	acmeContactEmail?: string;
	log: (msg: string) => void;
}): Promise<ObtainedCertificate>
{
	const client = new AcmeClient(params.provider);
	const stored = await loadAccount(params.kv, params.provider);
	const account = await client.createAccountOrLoad(
		stored,
		async () => {
			const kp = await generateEcP256KeyPair();
			return {
				jwkPrivate: await exportJwkPrivate(kp.privateKey),
				jwkPublic: await exportJwkPublic(kp.publicKey),
			};
		},
		async (state) => saveAccount(params.kv, params.provider, state),
		params.acmeContactEmail,
	);

	const identifiers = buildIdentifiers(params.domain, params.includeApexWithWildcard);
	const { order, orderUrl } = await client.newOrder(account, identifiers);

	const zoneId = await resolveZoneIdForDomain(params.cfApiToken, params.domain, params.zoneMap);

	// 做每个 authorization 的 dns-01
	for (const authzUrl of order.authorizations) {
		const { token, url: challengeUrl, identifier } = await client.getDns01ChallengeToken(account, authzUrl);
		const txtValue = await client.computeDns01TxtValue(account.jwkPublic, token);
		const recordName = dns01RecordName(identifier);

		params.log(`DNS-01 set TXT ${recordName}`);
		const { record, created } = await createTxtRecord(params.cfApiToken, zoneId, recordName, txtValue);
		try {
			if (params.dnsPropagationSeconds > 0) {
				await sleep(params.dnsPropagationSeconds * 1000);
			}
			await client.respondToChallenge(account, challengeUrl);
			await client.pollAuthorizationValid(account, authzUrl);
		} finally {
			if (created) {
				try {
					await deleteRecord(params.cfApiToken, zoneId, record.id);
				} catch (e) {
					params.log(`DNS cleanup failed (ignored): ${String(e)}`);
				}
			}
		}
	}

	// finalize
	const tlsKeys = await generateTlsKeyPair();
	const csrDer = await generateCsrDer(identifiers, tlsKeys);
	await client.finalizeOrder(account, order.finalize, csrDer);
	const validOrder = await client.pollOrderValid(account, orderUrl);
	if (!validOrder.certificate) throw new Error("ACME order valid but missing certificate URL");
	const certPem = await client.downloadCertificatePem(account, validOrder.certificate);
	const keyPem = await exportPrivateKeyPem(tlsKeys);

	// 解析 notAfter
	const { parseNotAfterFromPemChain } = await import("../certStore");
	const notAfter = parseNotAfterFromPemChain(certPem);

	return { certPem, keyPem, notAfter, provider: params.provider.provider };
}

function buildIdentifiers(domain: string, includeApexWithWildcard: boolean): string[] {
	const d = domain.toLowerCase();
	if (!d.startsWith("*.") || !includeApexWithWildcard) return [d];
	const apex = d.replace(/^\*\./, "");
	return [d, apex];
}

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}
