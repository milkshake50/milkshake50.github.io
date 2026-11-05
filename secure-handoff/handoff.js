"use strict";

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Vg9rS6vEsSGZo6gVlso
xZemInAxBOQhpOwCP3+9CLHukkhF9dhSquoNec84Eo5gkzzrtL5HYMhQvX+O3nuK
nmBmzqN3sVSZodvUhnbcriSQ1pOEbI7XvT47loP/ER/+wfeAcvb4IWXHQ/YKuzBr
t4kpxOSnlANPNVwwieF/pqC34i9qGCeeJJDsDEGLydYBBJwy/SNW19eml/ARifxi
kDbBWiiMua0BaHLEAr0aSy4NE9Ao2VeelEVvo9BF7e37RHoC6ppmQXIS7q1VWvRU
K4k5URVl8qTVr1eeqvuUiLDhsox1R6xZv2kXJXbAN7a5pbKLUtdDcH9MAGYycGhF
1Wb6ksYznoMqaug57W9u287pgt688/oMlQchG2hGkb4In+N4i8Mb248bF6MkcV0r
itf7+q4DwEnCR4THMJ+ilCC22IjS387VDBkkZEWXTF0HjZLjixjtcMcYMqNs0Esh
ylMU2u80DkLkIPpeJM430dl3eePNXHTcfw6OQslvoU8xAgMBAAE=
-----END PUBLIC KEY-----`;

const fileInput = document.getElementById("credential-file");
const encryptButton = document.getElementById("encrypt-button");
const showCodeButton = document.getElementById("show-code-button");
const status = document.getElementById("status");
const deviceCode = document.getElementById("device-code");

function pemToBytes(pem) {
  const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function validateGoogleClientFile(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("That file is not valid JSON.");
  }
  const clients = Object.values(parsed).filter(
    (value) => value && typeof value === "object" &&
      typeof value.client_id === "string" && typeof value.client_secret === "string"
  );
  if (clients.length !== 1) {
    throw new Error("That is not a Google OAuth client JSON file.");
  }
  return clients[0];
}

async function decryptDeviceCode(file) {
  const envelope = window.__VIBENEST_DEVICE_CODE__;
  if (!envelope || envelope.format !== "vibenest-device-code-v1") {
    throw new Error("No active Google device code is available.");
  }
  const client = validateGoogleClientFile(await file.text());
  const secretKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(client.client_secret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  const dataKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: Uint8Array.from(atob(envelope.salt_b64), (character) => character.charCodeAt(0)),
      info: new TextEncoder().encode("vibenest-device-code-v1"),
    },
    secretKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: Uint8Array.from(atob(envelope.iv_b64), (character) => character.charCodeAt(0)),
    },
    dataKey,
    Uint8Array.from(atob(envelope.ciphertext_b64), (character) => character.charCodeAt(0))
  );
  return new TextDecoder().decode(plaintext);
}

async function encryptCredentialFile(file) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("This browser does not support secure local encryption.");
  }
  if (file.size < 20 || file.size > 65536) {
    throw new Error("The selected file size is not valid for a Google OAuth client JSON file.");
  }
  const plaintext = new Uint8Array(await file.arrayBuffer());
  validateGoogleClientFile(new TextDecoder().decode(plaintext));

  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemToBytes(PUBLIC_KEY_PEM),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"]
  );
  const dataKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, plaintext)
  );
  const wrappedKey = new Uint8Array(
    await crypto.subtle.wrapKey("raw", dataKey, publicKey, { name: "RSA-OAEP" })
  );
  return {
    format: "hermes-oauth-handoff-v1",
    key_algorithm: "RSA-OAEP-3072-SHA256",
    data_algorithm: "AES-256-GCM",
    wrapped_key_b64: bytesToBase64(wrappedKey),
    iv_b64: bytesToBase64(iv),
    ciphertext_b64: bytesToBase64(ciphertext),
  };
}

function downloadPackage(payload) {
  const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "vibenest-oauth-client.encrypted.json";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

fileInput.addEventListener("change", () => {
  encryptButton.disabled = fileInput.files.length !== 1;
  showCodeButton.disabled = fileInput.files.length !== 1;
  deviceCode.textContent = "";
  status.textContent = fileInput.files.length === 1
    ? "File selected. Ready to encrypt locally."
    : "No file selected.";
});

showCodeButton.addEventListener("click", async () => {
  showCodeButton.disabled = true;
  status.textContent = "Decrypting the temporary code on this device…";
  try {
    deviceCode.textContent = await decryptDeviceCode(fileInput.files[0]);
    status.textContent = "Open google.com/device and enter the code shown below.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not reveal the code.";
  } finally {
    showCodeButton.disabled = fileInput.files.length !== 1;
  }
});

encryptButton.addEventListener("click", async () => {
  encryptButton.disabled = true;
  status.textContent = "Encrypting on this device…";
  try {
    const payload = await encryptCredentialFile(fileInput.files[0]);
    downloadPackage(payload);
    status.textContent = "Encrypted file downloaded. Send only the encrypted file to Hermes.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Encryption failed.";
  } finally {
    encryptButton.disabled = fileInput.files.length !== 1;
  }
});
