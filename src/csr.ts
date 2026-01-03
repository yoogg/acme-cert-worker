import * as x509 from "@peculiar/x509";

export async function generateCsrDer(domains: string[], keys: CryptoKeyPair): Promise<ArrayBuffer> {
	const algForSign = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
	const san = new x509.SubjectAlternativeNameExtension(
		domains.map((d) => ({ type: x509.DNS, value: d })),
		false,
	);
	const csr = await x509.Pkcs10CertificateRequestGenerator.create({
		name: `CN=${domains[0]}`,
		keys,
		signingAlgorithm: algForSign,
		extensions: [
			san,
			new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
		],
	});
	return csr.rawData;
}

export async function generateTlsKeyPair(): Promise<CryptoKeyPair> {
	// ECDSA P-256，证书体积小，Worker 生成快
	return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

export async function exportPrivateKeyPem(keys: CryptoKeyPair): Promise<string> {
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
	return derToPem(pkcs8, "PRIVATE KEY");
}

function derToPem(der: ArrayBuffer, label: string): string {
	const bytes = new Uint8Array(der);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	const base64 = btoa(binary);
	const chunks = base64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${chunks.join("\n")}\n-----END ${label}-----\n`;
}
