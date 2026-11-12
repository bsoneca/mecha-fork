-- The roles the cluster's services act as: anon and authenticator for
-- PostgREST, app_user and service for the auth plane's tokens, and electric
-- for the sync service.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authenticator') THEN
    CREATE ROLE authenticator NOINHERIT;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'service') THEN
    CREATE ROLE service NOLOGIN;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'electric') THEN
    CREATE ROLE electric NOLOGIN;
  END IF;
END
$$;

-- Every statement below that changes a role runs only when the role does not
-- already hold what it sets. Changing a role's attributes, memberships or
-- settings takes CREATEROLE (and BYPASSRLS or REPLICATION to set those), even
-- when nothing would change; a deployment whose roles are managed outside
-- (an operator, or a DBA on a managed database, made them with what this file
-- sets) runs this file with a login that holds none of those, and it changes
-- nothing. A role that lacks what it needs is still set, and that login's
-- missing privilege is the error.

-- PostgREST logs in as authenticator and switches to the role a request's
-- token names; it applies that role's settings (timeouts, isolation) only to
-- roles its login is granted, so the grant is what makes them hold, and the
-- login inherits none of their privileges. On Kubernetes the operator may
-- have created the role first.
--
-- A pipeline writes every tenant's rows, and electric reads every tenant's WAL:
-- both reach across scopes by a role attribute the audit can see. Without it
-- electric's current_scopes() is empty and every shape syncs empty, silently.
-- electric's password is the deployment's (cluster.cue's #RolePasswordsStep).
DO $$
DECLARE
  r text;
BEGIN
  IF NOT (SELECT rolcanlogin AND NOT rolinherit FROM pg_catalog.pg_roles WHERE rolname = 'authenticator') THEN
    ALTER ROLE authenticator NOINHERIT LOGIN;
  END IF;
  FOREACH r IN ARRAY ARRAY['anon', 'app_user', 'service'] LOOP
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members
                   WHERE roleid = r::regrole AND member = 'authenticator'::regrole) THEN
      EXECUTE format('GRANT %I TO authenticator', r);
    END IF;
  END LOOP;

  IF NOT (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = 'service') THEN
    ALTER ROLE service BYPASSRLS;
  END IF;
  IF NOT (SELECT rolbypassrls AND rolreplication AND rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = 'electric') THEN
    ALTER ROLE electric BYPASSRLS REPLICATION LOGIN;
  END IF;
END
$$;

-- The pipelines and the ticker write as `service` through crud, into any
-- table, as a caller's grants let them.
GRANT USAGE ON SCHEMA public TO service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO service;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO service;

-- Electric snapshots a shape's rows before it streams them.
GRANT USAGE ON SCHEMA public TO electric;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO electric;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO electric;

-- Finite machine bounds: statement, lock, and idle timeouts.
-- Public and client-facing traffic fail fast to protect connection pool and give immediate feedback;
-- the internal service role (batches, pipelines, ticker) has bounded headroom.
DO $$
DECLARE
  s record;
BEGIN
  FOR s IN SELECT * FROM (VALUES
    ('anon', 'statement_timeout', '5s'),
    ('anon', 'lock_timeout', '2s'),
    ('anon', 'idle_in_transaction_session_timeout', '10s'),
    ('authenticator', 'statement_timeout', '5s'),
    ('authenticator', 'lock_timeout', '2s'),
    ('authenticator', 'idle_in_transaction_session_timeout', '10s'),
    ('app_user', 'statement_timeout', '5s'),
    ('app_user', 'lock_timeout', '2s'),
    ('app_user', 'idle_in_transaction_session_timeout', '10s'),
    ('service', 'statement_timeout', '30s'),
    ('service', 'lock_timeout', '5s'),
    ('service', 'idle_in_transaction_session_timeout', '60s')
  ) AS v(role, setting, value) LOOP
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_db_role_setting
                   WHERE setdatabase = 0 AND setrole = s.role::regrole
                     AND s.setting || '=' || s.value = ANY (setconfig)) THEN
      EXECUTE format('ALTER ROLE %I SET %I = %L', s.role, s.setting, s.value);
    END IF;
  END LOOP;
END
$$;
