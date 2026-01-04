export function base64UrlEncode(data: ArrayBuffer | Uint8Array): string {
	const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	const b64 = btoa(binary);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecodeToBytes(value: string): Uint8Array {
	// Accept base64url or standard base64, with or without padding.
	const trimmed = value.trim().replace(/=+$/g, "");
	const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
	const b64 = normalized + "===".slice((normalized.length + 3) % 4);
	const binary = atob(b64);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}

export function utf8ToBytes(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
	return new TextDecoder().decode(bytes);
}
