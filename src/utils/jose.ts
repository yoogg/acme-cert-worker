import { base64UrlEncode, utf8ToBytes } from "./base64url";

export type JwkEcPublic = {
	kty: "EC";
	crv: "P-256";
	x: string;
	y: string;
};

export type JwkEcPrivate = JwkEcPublic & { d: string };

export function canonicalizeJwk(jwk: JwkEcPublic): JwkEcPublic {
	// ACME thumbprint 要求按字典序字段名序列化（crv,kty,x,y）
	return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
}

export async function jwkThumbprintBase64Url(jwk: JwkEcPublic): Promise<string> {
	const canonical = canonicalizeJwk(jwk);
	const json = JSON.stringify(canonical);
	const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(utf8ToBytes(json)));
	return base64UrlEncode(digest);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(ab).set(bytes);
	return ab;
}

export function base64UrlEncodeJson(obj: unknown): string {
	return base64UrlEncode(utf8ToBytes(JSON.stringify(obj)));
}

export function derEcdsaSigToJose(rawDer: ArrayBuffer, keySizeBytes: number): Uint8Array {
	// WebCrypto ECDSA sign 通常返回 ASN.1 DER SEQUENCE(INTEGER r, INTEGER s)
	const bytes = new Uint8Array(rawDer);
	let offset = 0;
	if (bytes[offset++] !== 0x30) throw new Error("Invalid ECDSA DER (no SEQ)");
	const seqLen = readDerLength(bytes, offset);
	offset = seqLen.nextOffset;
	const seqEnd = offset + seqLen.length;

	const r = readDerInteger(bytes, offset);
	offset = r.nextOffset;
	const s = readDerInteger(bytes, offset);
	offset = s.nextOffset;
	if (offset !== seqEnd) {
		// tolerate trailing? but better strict
	}

	const out = new Uint8Array(keySizeBytes * 2);
	out.set(leftPad(r.value, keySizeBytes), 0);
	out.set(leftPad(s.value, keySizeBytes), keySizeBytes);
	return out;
}

function leftPad(bytes: Uint8Array, length: number): Uint8Array {
	if (bytes.length === length) return bytes;
	if (bytes.length > length) return bytes.slice(bytes.length - length);
	const out = new Uint8Array(length);
	out.set(bytes, length - bytes.length);
	return out;
}

function readDerLength(bytes: Uint8Array, offset: number): { length: number; nextOffset: number } {
	const first = bytes[offset++];
	if (first === undefined) throw new Error("Invalid DER length");
	if ((first & 0x80) === 0) return { length: first, nextOffset: offset };
	const numBytes = first & 0x7f;
	if (numBytes === 0 || numBytes > 4) throw new Error("Invalid DER length bytes");
	let len = 0;
	for (let i = 0; i < numBytes; i++) {
		len = (len << 8) | bytes[offset++];
	}
	return { length: len, nextOffset: offset };
}

function readDerInteger(bytes: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
	if (bytes[offset++] !== 0x02) throw new Error("Invalid DER (no INTEGER)");
	const lenInfo = readDerLength(bytes, offset);
	offset = lenInfo.nextOffset;
	let value = bytes.slice(offset, offset + lenInfo.length);
	offset += lenInfo.length;
	// Strip leading 0x00 used to force positive integer
	while (value.length > 0 && value[0] === 0x00) value = value.slice(1);
	return { value, nextOffset: offset };
}
