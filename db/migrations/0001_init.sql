create table if not exists assets(
  id bigserial primary key,
  hostname text unique,
  ip text,
  os text,
  business_criticality int default 1,
  last_seen timestamptz default now()
);

create table if not exists packages(
  id bigserial primary key,
  asset_id bigint references assets(id) on delete cascade,
  name text,
  version text,
  cpe text
);

create index if not exists packages_asset_name_idx on packages(asset_id, name);

create table if not exists vulns(
  id bigserial primary key,
  cve_id text unique,
  cvss numeric,
  summary text,
  published timestamptz,
  cpe_matches jsonb
);

create table if not exists threat_iocs(
  id bigserial primary key,
  type text,
  value text,
  source text,
  first_seen timestamptz,
  last_seen timestamptz,
  severity int
);

create table if not exists findings(
  id bigserial primary key,
  asset_id bigint references assets(id),
  source text,
  type text,
  reference_id text,
  risk numeric,
  status text default 'open',
  created_at timestamptz default now()
);

create table if not exists actions(
  id bigserial primary key,
  finding_id bigint references findings(id),
  playbook text,
  params_json jsonb,
  status text default 'pending',
  started_at timestamptz,
  finished_at timestamptz,
  log text
);

create table if not exists audit_log(
  id bigserial primary key,
  actor text,
  action text,
  target text,
  at timestamptz default now(),
  meta jsonb
);
