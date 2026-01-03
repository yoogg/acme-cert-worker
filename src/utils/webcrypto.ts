import { base64UrlEncode, base64UrlDecodeToBytes, utf8ToBytes } from "./base64url";
import { derEcdsaSigToJose, type JwkEcPrivate, type JwkEcPublic } from "./jose";

export async function sha256Base64Url(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(utf8ToBytes(text)));
	return base64UrlEncode(digest);
}

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
	const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
	return new Uint8Array(digest);
}

export async function hmacSha256SignBase64Url(keyBase64Url: string, data: Uint8Array): Promise<string> {
	const keyBytes = base64UrlDecodeToBytes(keyBase64Url);
	const key = await crypto.subtle.importKey("raw", toArrayBuffer(keyBytes), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const sig = await crypto.subtle.sign("HMAC", key, toArrayBuffer(data));
	return base64UrlEncode(sig);
}

export async function generateEcP256KeyPair(): Promise<CryptoKeyPair> {
	return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

export async function exportJwkPublic(key: CryptoKey): Promise<JwkEcPublic> {
	const jwk = (await crypto.subtle.exportKey("jwk", key)) as unknown as JwkEcPublic;
	return jwk;
}

export async function exportJwkPrivate(key: CryptoKey): Promise<JwkEcPrivate> {
	const jwk = (await crypto.subtle.exportKey("jwk", key)) as unknown as JwkEcPrivate;
	return jwk;
}

export async function importEcPrivateKeyFromJwk(jwk: JwkEcPrivate): Promise<CryptoKey> {
	return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}

export async function importEcPublicKeyFromJwk(jwk: JwkEcPublic): Promise<CryptoKey> {
	return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

export async function signEs256Jws(
	privateKey: CryptoKey,
	protectedHeader: Record<string, unknown>,
	payload: Record<string, unknown> | string,
): Promise<{ protected: string; payload: string; signature: string }>
{
	const protectedB64 = base64UrlEncode(utf8ToBytes(JSON.stringify(protectedHeader)));
	const payloadB64 =
		typeof payload === "string" ? base64UrlEncode(utf8ToBytes(payload)) : base64UrlEncode(utf8ToBytes(JSON.stringify(payload)));

	const signingInput = utf8ToBytes(`${protectedB64}.${payloadB64}`);
	const derSig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, toArrayBuffer(signingInput));
	const joseSigBytes = derEcdsaSigToJose(derSig, 32);
	const sigB64 = base64UrlEncode(joseSigBytes);
	return { protected: protectedB64, payload: payloadB64, signature: sigB64 };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(ab).set(bytes);
	return ab;
}
