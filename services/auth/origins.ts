/**
 * The origins an Android app's passkey ceremonies carry. A native passkey made through Android's
 * Credential Manager names no web page: its clientDataJSON origin is the app's signing certificate,
 * `android:apk-key-hash:<the certificate's SHA-256, base64url, unpadded>`. The relying party is the
 * web's (WEBAUTHN_RP_ID), and Android has already checked, against the Digital Asset Links the door
 * serves, that the app may use it; the door then admits that origin beside its web one.
 *
 * WEBAUTHN_ANDROID_ORIGINS lists the fingerprints of the app's release signing certificates as
 * `keytool -list` and Play's console print them (`AB:CD:...`, 32 bytes), comma-separated. Empty or
 * unset admits none, so a door with no Android app is as before.
 */

/** A certificate's SHA-256 fingerprint as its apk-key-hash origin; throws on one that is not 32 bytes of hex. */
export function androidOrigin(fingerprint: string): string {
  const hex = fingerprint.trim().replace(/:/g, "");
  if (!/^[0-9A-Fa-f]{64}$/.test(hex)) {
    throw new Error(
      `WEBAUTHN_ANDROID_ORIGINS: ${fingerprint.trim()} is not a SHA-256 certificate fingerprint (32 bytes, AB:CD:...)`,
    );
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  const b64 = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `android:apk-key-hash:${b64}`;
}

/** WEBAUTHN_ANDROID_ORIGINS read: every fingerprint's origin, refused at startup if any is malformed. */
export function androidOrigins(list: string | undefined): string[] {
  return (list ?? "").split(",").map((f) => f.trim()).filter((f) => f.length > 0).map(androidOrigin);
}
