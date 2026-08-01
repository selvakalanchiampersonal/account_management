/* crypto.js
 * Small wrapper around Web Crypto (PBKDF2 + AES-GCM) so the vault
 * is encrypted at rest in localStorage. Everything happens in the
 * browser — the master password itself is never stored anywhere.
 */
const VaultCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function toBase64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function fromBase64(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
  }

  async function deriveKey(password, saltBytes) {
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: 210000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(password, plainObject) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const data = enc.encode(JSON.stringify(plainObject));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return {
      salt: toBase64(salt),
      iv: toBase64(iv),
      data: toBase64(cipherBuf)
    };
  }

  async function decrypt(password, payload) {
    const salt = new Uint8Array(fromBase64(payload.salt));
    const iv = new Uint8Array(fromBase64(payload.iv));
    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, fromBase64(payload.data)
    );
    return JSON.parse(dec.decode(plainBuf));
  }

  return { encrypt, decrypt };
})();
