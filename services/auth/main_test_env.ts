// Imported by main_test.ts ahead of main.ts, which reads its environment when it loads: the
// Android build the ceremonies below admit, by its signing certificate's SHA-256 fingerprint.
export const ANDROID_FINGERPRINT =
  "FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C";
Deno.env.set("WEBAUTHN_ANDROID_ORIGINS", ANDROID_FINGERPRINT);
// A session's lifetime from the environment (main.ts, USER_TOKEN_TTL_S): a day here, so a case can
// tell it from the week's default.
Deno.env.set("USER_TOKEN_TTL_S", "86400");
