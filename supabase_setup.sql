create table if not exists public.file_hash_registry (
    id bigint generated always as identity primary key,
    file_name text not null,
    file_name_key text not null,
    sha256 text not null check (sha256 ~ '^[0-9a-fA-F]{64}$'),
    file_size bigint not null default 0 check (file_size >= 0),
    created_at timestamptz not null default now(),
    constraint file_hash_registry_file_name_key_unique unique (file_name_key)
);

alter table public.file_hash_registry enable row level security;
