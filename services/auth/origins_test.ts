import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.13";
import { androidOrigin, androidOrigins } from "./origins.ts";

// The debug keystore's well-known shape: 32 bytes as keytool prints them.
const FP = "FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C";

Deno.test("a fingerprint is its apk-key-hash origin, base64url unpadded", () => {
  assertEquals(androidOrigin(FP), "android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w");
});

Deno.test("colons and case don't change the origin", () => {
  assertEquals(androidOrigin(FP.replace(/:/g, "").toLowerCase()), androidOrigin(FP));
});

Deno.test("unset or empty admits none", () => {
  assertEquals(androidOrigins(undefined), []);
  assertEquals(androidOrigins(""), []);
  assertEquals(androidOrigins(" , "), []);
});

Deno.test("a comma-separated list is every certificate's origin", () => {
  const other = "00".repeat(32);
  assertEquals(androidOrigins(` ${FP} , ${other}`), [androidOrigin(FP), androidOrigin(other)]);
});

Deno.test("a SHA-1 or a malformed fingerprint is refused", () => {
  assertThrows(() => androidOrigins("AB:CD:".repeat(10) + "AB"), Error, "is not a SHA-256 certificate fingerprint");
  assertThrows(() => androidOrigin("ZZ".repeat(32)), Error, "WEBAUTHN_ANDROID_ORIGINS");
});
