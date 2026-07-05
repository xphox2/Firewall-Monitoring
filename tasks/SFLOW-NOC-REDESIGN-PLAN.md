# sFlow NOC Reporting — Full Redesign Plan

> ## ⛔ SUPERSEDED — do not plan against this document
>
> **Status:** superseded / historical (originally "design / pre-implementation",
> authored 2026-06-11). Superseded by:
>
> - **`docs/FEATURE-ROADMAP.md` Part IV** — the authoritative v0.11 program
>   record (13 tranches),
> - the **sFlow analytics expansion** design (6 increments R1-R6; R1 —
>   app/L7 category + direction classification at ingest — **shipped
>   v0.10.505**),
> - **`docs/flow-protocol-research-2026-07-03.md`** — the NetFlow/IPFIX
>   design record.
>
> Key claims in the original plan no longer hold:
>
> - It targeted `0.11.0` → `0.15.0` as the sFlow-rewrite release window;
>   v0.11.0 actually shipped RBAC/access control, and v0.11.x is executing
>   the 13-tranche roadmap program.
> - It listed "IPFIX/NetFlow support" as an explicit non-goal; **NetFlow
>   v5/v9 + IPFIX ingestion shipped** as Tranche 3 (server v0.11.20 +
>   collector v1.3.0, migration v29).
> - It described the bytes × sampling_rate under-counting bug (1:512) as a
>   current defect; ingest has long since scaled by sampling rate (collector
>   and server parser both multiply — see `internal/database/flows.go`).
>
> The full 1,776-line original text remains available in git history
> (`git log --follow -- tasks/SFLOW-NOC-REDESIGN-PLAN.md`).

## What this plan was (tombstone summary)

A 2026-06-11 design for a 5-phase rewrite of the sFlow pipeline: correct
sampling-rate byte estimation, full sFlow v5 record-catalog parsing (IPv6,
extended records, counter samples, agent drops), a 100k+ samples/sec receiver
(SO_REUSEPORT worker pool, `pgx.CopyFrom` bulk insert), an in-memory 1 Hz
aggregator with SSE, and a purpose-built 6-zone `/admin/noc` page modeled on
Akvorado/sFlow-RT.

Much of its substance was later delivered through other work streams
(sampling-rate correctness, `flow_agent_drops`, flow rollups, the detection
engine, app/direction classification) and the remainder was re-scoped into
the sFlow analytics expansion increments and the Tranche 4 flow detection
engine backlog. Consult the superseding documents above for current state
and next steps.
