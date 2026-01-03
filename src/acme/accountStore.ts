import type { AcmeAccountState, AcmeProviderConfig } from "./client";

export function accountKvKey(provider: AcmeProviderConfig): string {
	return `acme:account:${stableHash(provider.directoryUrl)}`;
}

export async function loadAccount(kv: KVNamespace, provider: AcmeProviderConfig): Promise<AcmeAccountState | null> {
	const raw = await kv.get(accountKvKey(provider));
	if (!raw) return null;
	try {
		return JSON.parse(raw) as AcmeAccountState;
	} catch {
		return null;
	}
}

export async function saveAccount(kv: KVNamespace, provider: AcmeProviderConfig, state: AcmeAccountState): Promise<void> {
	await kv.put(accountKvKey(provider), JSON.stringify(state));
}

function stableHash(text: string): string {
	// 非密码学 hash：仅用于 KV key 稳定性
	let h = 2166136261;
	for (let i = 0; i < text.length; i++) {
		h ^= text.charCodeAt(i);
		h = Math.imul(h, 16777619);
	}
	return (h >>> 0).toString(16);
}
