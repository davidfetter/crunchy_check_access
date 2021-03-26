drop function if exists all_access(bool);
drop function if exists check_access(luser text, incl_sys bool, role_path text);

create or replace function check_access
(
  in luser text,
  in incl_sys bool,
  inout role_path text,
  out base_role text,
  out as_role text,
  out objtype text,
  out objid oid,
  out schemaname text,
  out objname text,
  out privname text
) returns setof record
language sql
as $$
WITH constant(c)AS (
    VALUES(
        json_build_object(
            'db_privs', ARRAY['CREATE', 'CONNECT', 'TEMPORARY', 'TEMP'],
            'tblspc_privs', ARRAY['CREATE'],
            'fdw_privs', ARRAY['USAGE'],
            'fdwsrv_privs', ARRAY['USAGE'],
            'lang_privs', ARRAY['USAGE'],
            'schema_privs', ARRAY['CREATE', 'USAGE'],
            'table_privs', ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'],
            'column_privs', ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'],
            'seq_privs', ARRAY['USAGE', 'SELECT', 'UPDATE'],
            'func_privs', ARRAY['EXECUTE'],
            'with_grant', ARRAY['', ' WITH GRANT OPTION'],
            'role_path', COALESCE(role_path, luser),
            'base_role', luser,
            'as_role', luser
        )
    )
)

/* Database privileges */
SELECT
    c0.c->>'role_path' AS role_path,
    c0.c->>'base_role' AS base_role,
    c0.c->>'as_role' AS as_role,
    'database' AS objtype,
    d.oid AS objid,
    NULL AS schemaname,
    pg_catalog.current_database()::text,
    db_privs.priv || with_grant.grantopt
FROM
    pg_catalog.pg_database d
CROSS JOIN
    constant c0
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c0.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c0.c->'db_privs') AS db_privs(priv)
WHERE
    d.datname=pg_catalog.current_database() AND
    pg_catalog.has_database_privilege(c0.c->>luser, pg_catalog.current_database(), priv || grantopt)

UNION ALL

/* Tablespace privileges */
SELECT
    c1.c->>'role_path' AS role_path,
    c1.c->>'base_role' AS base_role,
    c1.c->>'as_role' AS as_role,
    'tablespace' AS objtype,
    t.oid AS objid, /* objid */
    NULL AS schemaname, /* schemaname */
    t.spcname, /* objname */
    tblspc_privs.priv || with_grant.grantopt
FROM
    constant c1
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c1.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c1.c->'tblspc_privs') AS tblspc_privs(priv)
CROSS JOIN
    pg_catalog.pg_tablespace t
WHERE
    t.spcname !~ '^pg_' AND
    pg_catalog.has_tablespace_privilege(luser, t.spcname, tblspc_privs.priv || with_grant.grantopt)

UNION ALL

/* Foreign data wrapper privileges */
SELECT
    c2.c->>'role_path' AS role_path,
    c2.c->>'base_role' AS base_role,
    c2.c->>'as_role' AS as_role,
    'fdw' AS objtype,
    f.oid AS objid, /* objid */
    NULL AS schemaname, /* schemaname */
    f.fdwname, /* objname */
    fdw_privs.priv || with_grant.grantopt
FROM
    constant c2
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c2.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c2.c->'fdw_privs') AS fdw_privs(priv)
CROSS JOIN
    pg_catalog.pg_foreign_data_wrapper f
WHERE
    pg_catalog.has_foreign_data_wrapper_privilege(luser, f.fdwname, fdw_privs.priv || with_grant.grantopt)

UNION ALL

/* Foreign server privileges */
SELECT
    c3.c->>'role_path' AS role_path,
    c3.c->>'base_role' AS base_role,
    c3.c->>'as_role' AS as_role,
    'server' AS objtype,
    s.oid AS objid, /* objid */
    NULL AS schemaname, /* schemaname */
    s.srvname, /* objname */
    fdwsrv_privs.priv || with_grant.grantopt
FROM
    constant c3
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c3.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c3.c->'fdwsrv_privs') AS fdwsrv_privs(priv)
CROSS JOIN
    pg_catalog.pg_foreign_server s
WHERE
    pg_catalog.has_server_privilege(luser, s.srvname, fdwsrv_privs.priv || with_grant.grantopt)

UNION ALL

/* Language privileges */
SELECT
    c4.c->>'role_path' AS role_path,
    c4.c->>'base_role' AS base_role,
    c4.c->>'as_role' AS as_role,
    'server' AS objtype,
    l.oid AS objid, /* objid */
    NULL AS schemaname, /* schemaname */
    l.lanname, /* objname */
    lang_privs.priv || with_grant.grantopt
FROM
    constant c4
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c4.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c4.c->'lang_privs') AS lang_privs(priv)
CROSS JOIN
    pg_catalog.pg_language l
CROSS JOIN
    (SELECT rolsuper FROM pg_catalog.pg_authid WHERE rolname = luser) AS a
WHERE
    pg_catalog.has_language_privilege(luser, l.lanname, lang_privs.priv || with_grant.grantopt) OR
    a.rolsuper OR
    l.lanpltrusted

UNION ALL

/* Schema privileges */
SELECT
    c5.c->>'role_path' AS role_path,
    c5.c->>'base_role' AS base_role,
    c5.c->>'as_role' AS as_role,
    'schema' AS objtype,
    n.oid AS objid, /* objid */
    NULL AS schemaname, /* schemaname */
    n.nspname::text, /* objname */
    schema_privs.priv || with_grant.grantopt
FROM
    constant c5
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c5.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c5.c->'schema_privs') AS schema_privs(priv)
CROSS JOIN
    pg_catalog.pg_namespace n
WHERE
    incl_sys OR n.nspname !~ '^(pg_|information_schema$)'

UNION ALL

/* Function privileges */
SELECT
    c6.c->>'role_path' AS role_path,
    c6.c->>'base_role' AS base_role,
    c6.c->>'as_role' AS as_role,
    'function' AS objtype,
    p.oid AS objid, /* objid */
    n.nspname AS schemaname, /* schemaname */
    pg_catalog.format('%s(%s)', p.proname,pg_catalog.pg_get_function_arguments(p.oid)), /* function signature */
    CASE WHEN pg_catalog.has_function_privilege(luser, objid, function_privs.priv || with_grant.grantopt) THEN
        function_privs.priv || with_grant.grantopt
    ELSE
        function_privs.priv
    END
FROM
    constant c6
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c6.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c6.c->'function_privs') AS function_privs(priv)
CROSS JOIN
    pg_catalog.pg_proc p
JOIN
    pg_catalog.pg_namespace n
    ON (p.pronamespace = n.oid)
WHERE
    pg_catalog.has_schema_privilege(luser, n.nspname, 'usage') AND
    ( incl_sys OR n.nspname !~ '^(pg_|information_schema$)')

UNION ALL

/* Table privileges */
SELECT
    c7.c->>'role_path' AS role_path,
    c7.c->>'base_role' AS base_role,
    c7.c->>'as_role' AS as_role,
    'table' AS objtype,
    c.oid AS objid, /* objid */
    n.nspname::text schemaname, /* schemaname */
    c.relname, /* objname */
    schema_privs.priv || with_grant.grantopt
FROM
    constant c7
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c7.c->'with_grant') AS with_grant(grantopt)
CROSS JOIN LATERAL
    pg_catalog.json_array_elements_text(c7.c->'schema_privs') AS schema_privs(priv)
CROSS JOIN
    pg_catalog.pg_class c
JOIN
    pg_catalog.pg_namespace n
    ON (c.relnamespace = n.oid)
WHERE
    relkind='r'
    incl_sys OR n.nspname !~ '^(pg_|information_schema$)'
$$;


create or replace function all_access(
      in incl_sys bool,
      out role_path text,
      out base_role text,
      out as_role text,
      out objtype text,
      out objid oid,
      out schemaname text,
      out objname text,
      out privname text
)
returns setof record
language sql
as $$
SELECT
    c.*
FROM
    pg_catalog.pg_authid a
CROSS JOIN LATERAL
    check_access(a.rolname, incl_sys) AS c
)
$$;
