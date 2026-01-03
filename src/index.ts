import { parseAllowedDomains, parseCaProviders, parseIntEnv, parseZoneMap } from "./env";
import type { Env } from "./env";
import { loadCachedCert, saveCachedCert, daysUntil } from "./certStore";
import { obtainCertificateWithFallback } from "./acme/obtain";

type ExecutionContextLike = { waitUntil(promise: Promise<unknown>): void };

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
		try {
			const url = new URL(request.url);

			if (url.pathname === "/health") {
				return Response.json({ ok: true });
			}

			if (url.pathname !== "/cert" && url.pathname !== "/key") {
				return new Response("Not Found", { status: 404 });
			}

			const auth = request.headers.get("authorization") ?? "";
			const expected = `Bearer ${env.AUTH_TOKEN}`;
			if (!env.AUTH_TOKEN || auth !== expected) {
				return new Response("Unauthorized", { status: 401 });
			}

			const domain = (url.searchParams.get("domain") ?? "").trim().toLowerCase();
			if (!domain) {
				return new Response("Missing domain", { status: 400 });
			}

			const allowed = parseAllowedDomains(env.ALLOWED_DOMAINS);
			if (!isDomainAllowed(domain, allowed)) {
				return new Response("Domain not allowed", { status: 403 });
			}

			const material = await getOrRenewCertificateMaterial(domain, env, ctx);
			if (url.pathname === "/cert") {
				return Response.json({
					domain,
					provider: material.provider,
					notAfter: material.notAfterIso,
					certPem: material.certPem,
					cached: material.cached,
				});
			}
			return Response.json({
				domain,
				provider: material.provider,
				notAfter: material.notAfterIso,
				keyPem: material.keyPem,
				cached: material.cached,
			});
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			console.error("Worker error:", message);
			return Response.json({ error: "worker_exception", message }, { status: 500 });
		}
	},
};

async function getOrRenewCertificateMaterial(domain: string, env: Env, ctx: ExecutionContextLike): Promise<{
	domain: string;
	certPem: string;
	keyPem: string;
	notAfterIso: string;
	provider: string;
	cached: boolean;
}> {
	const renewBeforeDays = parseIntEnv(env.RENEW_BEFORE_DAYS, 30);
	const dnsWaitSeconds = parseIntEnv(env.DNS_PROPAGATION_SECONDS, 20);
	const providers = parseCaProviders(env.CA_PROVIDERS_JSON);
	const zoneMap = parseZoneMap(env.CF_ZONE_MAP_JSON);

	if (!env.CF_API_TOKEN) throw new Error("Missing CF_API_TOKEN");
	if (providers.length === 0) throw new Error("Missing/invalid CA_PROVIDERS_JSON");
	if (zoneMap.length === 0) throw new Error("Missing/invalid CF_ZONE_MAP_JSON");

	const cached = await loadCachedCert(env.CERTS_KV, domain);
	if (cached) {
		const notAfter = new Date(cached.notAfterIso);
		if (Number.isFinite(notAfter.getTime())) {
			const left = daysUntil(notAfter);
			if (left >= renewBeforeDays) {
				return { ...cached, cached: true };
			}
		}
	}

	const log = (msg: string) => console.log(`[cert:${domain}] ${msg}`);
	const obtained = await obtainCertificateWithFallback({
		providers,
		kv: env.CERTS_KV,
		domain,
		includeApexWithWildcard: true,
		cfApiToken: env.CF_API_TOKEN,
		zoneMap,
		dnsPropagationSeconds: dnsWaitSeconds,
		log,
	});

	const saved = {
		domain,
		certPem: obtained.certPem,
		keyPem: obtained.keyPem,
		notAfterIso: obtained.notAfter.toISOString(),
		provider: obtained.provider,
		updatedAtIso: new Date().toISOString(),
	};
	ctx.waitUntil(saveCachedCert(env.CERTS_KV, saved));
	return { ...saved, cached: false };
}

function isDomainAllowed(domain: string, allowed: string[]): boolean {
	// 允许精确域名（example.com）或通配（*.example.com）
	if (!/^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]+$/.test(domain)) return false;
	for (const entry of allowed) {
		const normalized = entry.trim().toLowerCase();
		if (!normalized) continue;
		if (normalized === domain) return true;
		if (normalized.startsWith("*.") && domain.endsWith(normalized.slice(1))) {
			// 允许 *.example.com 匹配 foo.example.com（以及 *.example.com 本身如果请求就是 *.example.com）
			return true;
		}
	}
	return false;
}
