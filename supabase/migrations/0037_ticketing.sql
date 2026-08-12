-- =============================================================================
-- 0037 — Ticketing Integration
-- =============================================================================
-- Adds:
--   1. tickets table — tracks tickets created in external systems (ServiceNow, etc.)
--      References connection_registry.tool for the provider config.
--   2. Registers ServiceNow in connection_registry as a ticketing tool.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. tickets — one row per created ticket
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tickets (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    remediation_package_id  bigint NOT NULL REFERENCES remediation_packages(id),
    connection_tool         text NOT NULL,           -- FK to connection_registry.tool

    -- External ticket reference
    external_ticket_id      text,           -- e.g. "INC0012345" (ServiceNow)
    external_ticket_url     text,           -- full URL to the ticket in the provider UI
    provider                text NOT NULL,  -- 'servicenow', 'jira', 'webhook', etc.

    -- Lifecycle
    status                  text NOT NULL DEFAULT 'pending',
    -- pending     → creation request queued
    -- created     → ticket exists in external system
    -- synced      → latest status pulled from provider
    -- failed      → creation or sync failed (see error_message)
    -- closed      → ticket closed in external system

    error_message           text,           -- last error if status = 'failed'

    -- Ticket content snapshot (what was sent to the provider)
    title                   text NOT NULL,
    description             text,
    priority                text,           -- mapped from severity: Critical→P1, High→P2, etc.
    labels                  text[] DEFAULT '{}',

    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    synced_at               timestamptz,    -- last time we pulled status from provider

    CONSTRAINT tickets_status_check
        CHECK (status IN ('pending', 'created', 'synced', 'failed', 'closed'))
);

-- Lookup tickets by package (most common query)
CREATE INDEX IF NOT EXISTS idx_tickets_package_id
    ON tickets (remediation_package_id);

-- Lookup tickets by status (dashboards: "show all failed tickets")
CREATE INDEX IF NOT EXISTS idx_tickets_status
    ON tickets (status) WHERE status IN ('pending', 'failed');

-- ---------------------------------------------------------------------------
-- 2. Register ServiceNow in connection_registry
-- ---------------------------------------------------------------------------
INSERT INTO connection_registry (tool, protocol, auth_type, endpoint, auth_ref, metadata, enabled)
VALUES (
    'servicenow-ticket',
    'REST',
    'basic',
    '',  -- Set via env var SERVICENOW_INSTANCE_URL or PATCH /admin/scanners/servicenow-ticket
    'env:servicenow',
    '{"connector_type": "servicenow_ticket"}'::jsonb,
    true
)
ON CONFLICT (tool) DO NOTHING;
