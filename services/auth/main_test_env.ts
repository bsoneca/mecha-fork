// Imported by main_test.ts ahead of main.ts, which reads its environment when it loads: a session's
// lifetime from the environment (main.ts, USER_TOKEN_TTL_S), a day here, so a case can tell it from
// the week's default.
Deno.env.set("USER_TOKEN_TTL_S", "86400");
