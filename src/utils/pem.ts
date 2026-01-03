export function pemToDer(pem: string): ArrayBuffer {
	const lines = pem
		.replace(/\r/g, "")
		.split("\n")
		.filter((l) => !l.startsWith("-----"))
		.join("");
	const binary = atob(lines);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes.buffer;
}

export function extractFirstCertificatePem(pemChain: string): string {
	const match = pemChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
	if (!match) throw new Error("No CERTIFICATE block found");
	return match[0];
}

export function derToPem(der: ArrayBuffer, label: string): string {
	const bytes = new Uint8Array(der);
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	const base64 = btoa(binary);
	const chunks = base64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${chunks.join("\n")}\n-----END ${label}-----\n`;
}
