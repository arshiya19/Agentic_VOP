# Supabase migrations

SQL migrations for the Agentic_VOP project (`agentic-vop-dev`).

## Apply a migration

Open the **Supabase Dashboard** for `agentic-vop-dev` → **SQL Editor** → **New query** → paste the contents of the migration file → **Run**.

That's it. No CLI required.

## Migrations

| File | What it creates |
|---|---|
| `migrations/0001_initial_schema.sql` | The 6 v1 tables: `agent_runs`, `agent_trace_events`, `issues`, `connection_registry`, `schema_mapping`, `prompt_db` |
| `migrations/0002_seed_tenable_v1.sql` | Seeds for the Tenable pilot: 1 row in `connection_registry`, ~13 rows in `schema_mapping`, 1 row in `prompt_db`. Idempotent — safe to re-run. |

## After applying 0001

Quick sanity check — run this in the SQL Editor:

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

Should list all 6 tables.

## Notes

- Realtime is enabled on `agent_trace_events`, `agent_runs`, and `issues` — the frontend can subscribe to live updates.
- RLS (Row-Level Security) is enabled on all tables. Authenticated users can read; backend writes via service-role key (which bypasses RLS).
- `event_id` on `agent_runs` is the idempotency key — if the same `event_id` is submitted twice, the DB rejects the duplicate.
- `fingerprint` on `issues` is the cross-scanner dedup key — same vulnerability + same asset from different scanners = one row.
