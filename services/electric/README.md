# Electric image

The cluster uses the same pinned Electric 1.8.1 release on AMD64 and ARM64. Its image build runs `patch.exs` with the release's own Elixir compiler.

Electric accepts snapshot callers before asynchronous shape initialization finishes. `State.initialize` replaces the initial snapshot state and loses those callers. The snapshot can finish successfully while their HTTP requests wait until the 45-second timeout. The patch carries the waiting callers into the initialized state.

The build downloads one upstream source module from an immutable commit, verifies its SHA-256, changes one expression, compiles it and tests the actual consumer callbacks before writing the resulting module. Fetching the pinned source keeps its implementation upstream; the checksum and exact replacement prevent an upstream change from silently applying a different patch. No application starts and no database is needed during the build, but Electric's configuration reader requires placeholder `DATABASE_URL` and `ELECTRIC_SECRET` values.

The embedded regression covers early and late callers, fresh and restored snapshots, readiness replies and duplicate notifications. Run it against an unpatched image with `MECHA_ELECTRIC_TEST_ONLY=1` to demonstrate the failure. A future version bump must first pass that mode unmodified; then remove the patch and its image-build wiring together.

With `ELECTRIC_MANUAL_TABLE_PUBLISHING` the cluster creates the publication and its tables (`008_publication.sql`), and the electric role holds no `CREATE` on the database. Electric still issues `CREATE PUBLICATION` at every start; PostgreSQL checks the privilege before the name, so the database logs `permission denied for database` before Electric falls back to finding the publication. The second patch gives `Electric.Application` the option Electric already has, `try_creating_publication?`, as the opposite of manual publishing, so it no longer tries; its regression checks both settings. Electric's [application.ex at 0f404200](https://github.com/electric-sql/electric/blob/0f404200402f918a4b1596bc5c8a53479a435349/packages/sync-service/lib/electric/application.ex) is its source.

Upstream source: [Electric State at 0f404200](https://github.com/electric-sql/electric/blob/0f404200402f918a4b1596bc5c8a53479a435349/packages/sync-service/lib/electric/shapes/consumer/state.ex), under the upstream [Apache 2.0 license](https://github.com/electric-sql/electric/blob/0f404200402f918a4b1596bc5c8a53479a435349/LICENSE).
