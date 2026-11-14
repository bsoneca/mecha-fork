import { assert, assertStringIncludes } from "jsr:@std/assert@1.0.13";
import { apiKeysSql, handoffSpentSql } from "./schema.ts";

// The auth service's own tables follow the cluster's schemas (meta.schema): app_user is the app's,
// the audit's list mecha's. The defaults spell what an earlier release did.
Deno.test("the key and handoff tables name the cluster's schemas", () => {
  const keys = apiKeysSql({ app: "shop", mecha: "lists" });
  assertStringIncludes(keys, "references shop.app_user(id)");
  assertStringIncludes(keys, "JOIN shop.app_user u");
  assertStringIncludes(keys, "INSERT INTO lists.rls_exempt");
  assert(!/\bpublic\.|\bmecha\./.test(keys), keys);
  const spent = handoffSpentSql({ app: "shop", mecha: "lists" });
  assertStringIncludes(spent, "INSERT INTO lists.rls_exempt");
  assert(!/\bmecha\./.test(spent), spent);
  assertStringIncludes(apiKeysSql(), "references public.app_user(id)");
  assertStringIncludes(handoffSpentSql(), "INSERT INTO mecha.rls_exempt");
});
