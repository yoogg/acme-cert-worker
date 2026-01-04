import { base64UrlEncode, utf8ToBytes } from "../utils/base64url";
import { base64UrlEncodeJson, jwkThumbprintBase64Url, type JwkEcPrivate, type JwkEcPublic } from "../utils/jose";
import { hmacSha256SignBase64Url, importEcPrivateKeyFromJwk, signEs256Jws } from "../utils/webcrypto";
import type { AcmeAuthorization, AcmeDirectory, AcmeOrder } from "./types";

export type AcmeProviderConfig = {
	provider: string;
	directoryUrl: string;
	eab?: { kid: string; hmacKeyBase64url: string };
};

export type AcmeAccountState = {
	directoryUrl: string;
	kid: string;
	jwkPrivate: JwkEcPrivate;
	jwkPublic: JwkEcPublic;
};

export class AcmeClient {
	private directory?: AcmeDirectory;
	private nonce?: string;

	constructor(private readonly config: AcmeProviderConfig) {}

	async getDirectory(): Promise<AcmeDirectory> {
		if (this.directory) return this.directory;

		// 缓存 ACME directory（通常很稳定），降低每次冷启动都外呼导致的 525 风险
		// 注意：Cache API 仅支持 GET；directory 正好是 GET。
		const cache = await caches.open("acme-directory");
		const cacheKey = new Request(this.config.directoryUrl, {
			method: "GET",
			headers: { accept: "application/json" },
		});
		const cached = await cache.match(cacheKey);
		if (cached) {
			try {
				const dir = (await cached.json()) as AcmeDirectory;
				this.directory = dir;
				return dir;
			} catch {
				// ignore cache parse errors and refetch
			}
		}

		const res = await fetchWithRetry(
			this.config.directoryUrl,
			{ headers: { accept: "application/json" } },
			6,
		);
		if (!res.ok) {
			const text = await safeReadText(res);
			const server = res.headers.get("server") ?? "";
			const cfRay = res.headers.get("cf-ray") ?? "";
			const extra = [
				server ? `server=${server}` : "",
				cfRay ? `cf-ray=${cfRay}` : "",
			]
				.filter(Boolean)
				.join(" ");
			throw new Error(`ACME directory fetch failed: ${res.status} ${this.config.directoryUrl} ${extra} ${text}`.trim());
		}
		const bodyText = await res.text();
		const dir = JSON.parse(bodyText) as AcmeDirectory;

		// 写入缓存（1 天），避免频繁外呼
		await cache.put(
			cacheKey,
			new Response(bodyText, {
				headers: {
					"content-type": "application/json; charset=utf-8",
					"cache-control": "public, max-age=86400",
				},
			}),
		);
		this.directory = dir;
		return dir;
	}

	async newNonce(): Promise<string> {
		const dir = await this.getDirectory();
		const res = await fetchWithRetry(dir.newNonce, { method: "HEAD" });
		const nonce = res.headers.get("replay-nonce");
		if (!nonce) throw new Error("ACME newNonce missing replay-nonce");
		this.nonce = nonce;
		return nonce;
	}

	private async ensureNonce(): Promise<string> {
		return this.nonce ?? this.newNonce();
	}

	private captureNonce(res: Response): void {
		const nonce = res.headers.get("replay-nonce");
		if (nonce) this.nonce = nonce;
	}

	async signedRequest<T>(
		url: string,
		account: { kid: string } | { jwkPublic: JwkEcPublic },
		jwkPrivate: JwkEcPrivate,
		payload: unknown | "POST_AS_GET",
	): Promise<{ body: T; headers: Headers; location?: string }>
	{
		const nonce = await this.ensureNonce();
		const privateKey = await importEcPrivateKeyFromJwk(jwkPrivate);

		const protectedHeader: Record<string, unknown> = {
			alg: "ES256",
			nonce,
			url,
		};
		if ("kid" in account) protectedHeader.kid = account.kid;
		else protectedHeader.jwk = account.jwkPublic;

		const jws = await signEs256Jws(privateKey, protectedHeader, payload === "POST_AS_GET" ? "" : (payload as any));
		const res = await fetchWithRetry(url, {
			method: "POST",
			headers: {
				"content-type": "application/jose+json",
				accept: "application/json",
			},
			body: JSON.stringify(jws),
		});
		this.captureNonce(res);
		const location = res.headers.get("location") ?? undefined;
		const contentType = res.headers.get("content-type") ?? "";

		if (!res.ok) {
			const text = await safeReadText(res);
			throw new Error(`ACME request failed ${res.status} ${url}: ${text.slice(0, 2000)}`);
		}

		if (contentType.includes("application/pem-certificate-chain")) {
			return { body: (await res.text()) as unknown as T, headers: res.headers, location };
		}

		if (res.status === 204) {
			return { body: undefined as unknown as T, headers: res.headers, location };
		}

		const json = (await res.json()) as T;
		return { body: json, headers: res.headers, location };
	}

	async createAccountOrLoad(
		stored: AcmeAccountState | null,
		generateAccount: () => Promise<{ jwkPrivate: JwkEcPrivate; jwkPublic: JwkEcPublic }>,
		save: (state: AcmeAccountState) => Promise<void>,
		contactEmail?: string,
	): Promise<AcmeAccountState>
	{
		if (stored && stored.directoryUrl === this.config.directoryUrl && stored.kid) return stored;

		const dir = await this.getDirectory();
		const { jwkPrivate, jwkPublic } = await generateAccount();

		const payload: Record<string, unknown> = {
			termsOfServiceAgreed: true,
		};
		const email = (contactEmail ?? "").trim();
		if (email) {
			payload.contact = [email.startsWith("mailto:") ? email : `mailto:${email}`];
		}

		if (this.config.eab) {
			payload.externalAccountBinding = await this.createExternalAccountBinding(dir.newAccount, this.config.eab.kid, this.config.eab.hmacKeyBase64url, jwkPublic);
		}

		const result = await this.signedRequest<Record<string, unknown>>(
			dir.newAccount,
			{ jwkPublic },
			jwkPrivate,
			payload,
		);
		const kid = result.location;
		if (!kid) throw new Error("ACME newAccount missing Location (kid)");

		const state: AcmeAccountState = {
			directoryUrl: this.config.directoryUrl,
			kid,
			jwkPrivate,
			jwkPublic,
		};
		await save(state);
		return state;
	}

	private async createExternalAccountBinding(
		newAccountUrl: string,
		eabKid: string,
		hmacKeyBase64Url: string,
		accountJwk: JwkEcPublic,
	): Promise<{ protected: string; payload: string; signature: string }>
	{
		const protectedHeader = {
			alg: "HS256",
			kid: eabKid,
			url: newAccountUrl,
		};
		const protectedB64 = base64UrlEncodeJson(protectedHeader);
		const payloadB64 = base64UrlEncodeJson(accountJwk);
		const data = utf8ToBytes(`${protectedB64}.${payloadB64}`);
		const signature = await hmacSha256SignBase64Url(hmacKeyBase64Url, data);
		return { protected: protectedB64, payload: payloadB64, signature };
	}

	async newOrder(account: AcmeAccountState, dnsIdentifiers: string[]): Promise<{ order: AcmeOrder; orderUrl: string }>
	{
		const dir = await this.getDirectory();
		const payload = {
			identifiers: dnsIdentifiers.map((d) => ({ type: "dns", value: d })),
		};
		const result = await this.signedRequest<AcmeOrder>(dir.newOrder, { kid: account.kid }, account.jwkPrivate, payload);
		const orderUrl = result.location;
		if (!orderUrl) throw new Error("ACME newOrder missing Location");
		return { order: result.body, orderUrl };
	}

	async getAuthorization(account: AcmeAccountState, authorizationUrl: string): Promise<AcmeAuthorization> {
		const result = await this.signedRequest<AcmeAuthorization>(authorizationUrl, { kid: account.kid }, account.jwkPrivate, "POST_AS_GET");
		return result.body;
	}

	async respondToChallenge(account: AcmeAccountState, challengeUrl: string): Promise<void> {
		await this.signedRequest<Record<string, never>>(challengeUrl, { kid: account.kid }, account.jwkPrivate, {});
	}

	async pollAuthorizationValid(account: AcmeAccountState, authorizationUrl: string, timeoutMs = 120_000): Promise<void> {
		// 轮询会产生大量 subrequests；使用退避减少请求次数，避免触发 Workers 的 "Too many subrequests"。
		const start = Date.now();
		let delayMs = 2000;
		let attempts = 0;
		const maxAttempts = 12;
		while (true) {
			const authz = await this.getAuthorization(account, authorizationUrl);
			if (authz.status === "valid") return;
			if (authz.status === "invalid") throw new Error(`ACME authorization invalid: ${authorizationUrl}`);
			if (Date.now() - start > timeoutMs) throw new Error(`ACME authorization timeout: ${authorizationUrl}`);
			if (attempts++ >= maxAttempts) throw new Error(`ACME authorization poll exceeded attempts: ${authorizationUrl}`);
			await sleep(delayMs);
			delayMs = Math.min(Math.floor(delayMs * 1.7), 10_000);
		}
	}

	async finalizeOrder(account: AcmeAccountState, finalizeUrl: string, csrDer: ArrayBuffer): Promise<void> {
		const payload = {
			csr: base64UrlEncode(csrDer),
		};
		await this.signedRequest<Record<string, unknown>>(finalizeUrl, { kid: account.kid }, account.jwkPrivate, payload);
	}

	async pollOrderValid(account: AcmeAccountState, orderUrl: string, timeoutMs = 180_000): Promise<AcmeOrder> {
		const start = Date.now();
		let delayMs = 2000;
		let attempts = 0;
		const maxAttempts = 12;
		while (true) {
			const result = await this.signedRequest<AcmeOrder>(orderUrl, { kid: account.kid }, account.jwkPrivate, "POST_AS_GET");
			const order = result.body;
			if (order.status === "valid") return order;
			if (order.status === "invalid") throw new Error(`ACME order invalid: ${orderUrl}`);
			if (Date.now() - start > timeoutMs) throw new Error(`ACME order timeout: ${orderUrl}`);
			if (attempts++ >= maxAttempts) throw new Error(`ACME order poll exceeded attempts: ${orderUrl}`);
			await sleep(delayMs);
			delayMs = Math.min(Math.floor(delayMs * 1.7), 10_000);
		}
	}

	async downloadCertificatePem(account: AcmeAccountState, certificateUrl: string): Promise<string> {
		const result = await this.signedRequest<string>(certificateUrl, { kid: account.kid }, account.jwkPrivate, "POST_AS_GET");
		return result.body;
	}

	async getDns01ChallengeToken(account: AcmeAccountState, authorizationUrl: string): Promise<{ token: string; url: string; identifier: string }>
	{
		const authz = await this.getAuthorization(account, authorizationUrl);
		const challenge = authz.challenges.find((c) => c.type === "dns-01");
		if (!challenge) throw new Error("ACME dns-01 challenge not found");
		return { token: challenge.token, url: challenge.url, identifier: authz.identifier.value };
	}

	async computeDns01TxtValue(accountJwk: JwkEcPublic, token: string): Promise<string> {
		const thumbprint = await jwkThumbprintBase64Url(accountJwk);
		const keyAuth = `${token}.${thumbprint}`;
		const bytes = utf8ToBytes(keyAuth);
		const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
		return base64UrlEncode(digest);
	}
}

async function fetchWithRetry(url: string, init: RequestInit, retries = 3): Promise<Response> {
	const transient = new Set([408, 425, 429, 500, 502, 503, 504, 522, 524, 525]);
	let lastError: unknown;
	for (let attempt = 0; attempt <= retries; attempt++) {
		try {
			const res = await fetch(url, init);
			if (!transient.has(res.status) || attempt === retries) return res;
			await sleep(backoffMs(attempt));
			continue;
		} catch (e) {
			lastError = e;
			if (attempt === retries) throw e;
			await sleep(backoffMs(attempt));
		}
	}
	throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function backoffMs(attempt: number): number {
	// 250ms, 1000ms, 2500ms, 4000ms, 6000ms, 9000ms, 12000ms...
	const table = [250, 1000, 2500, 4000, 6000, 9000, 12000];
	const base = table[Math.min(attempt, table.length - 1)];
	// 轻微抖动，避免所有请求同一时间重试
	const jitter = Math.floor(Math.random() * 200);
	return base + jitter;
}

async function safeReadText(res: Response): Promise<string> {
	try {
		const t = await res.text();
		return t.length > 300 ? t.slice(0, 300) : t;
	} catch {
		return "";
	}
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(ab).set(bytes);
	return ab;
}

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}
