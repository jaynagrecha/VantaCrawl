# Verifier capability backlog (post Phase 1)

Prioritized unsupported / incomplete families relative to the Horizon Catalog.

## Phase 2

| Family | Gap | Notes |
|--------|-----|-------|
| IDOR / access control | Dual-identity sessions | Need controlled accounts |
| Auth / session | Fixation, reset tokens, enumeration | Fixture-safe workflows only |
| CORS | Credentialed browser-read proof | Severity depends on credentials |
| JWT | Server acceptance of altered token | Not static inspection alone |
| Upload | Inert files + public retrieve | Execution only in Lab |
| API / infra exposure | GraphQL, Actuator, ES, .env | Differentiate metadata vs secrets |
| WebSocket | Origin + auth handshake | Fixture-safe messages |

## Phase 3

| Family | Gap | Notes |
|--------|-----|-------|
| Business logic | Workflow-aware state machines | Controlled balances + cleanup |
| Race conditions | Lab-only concurrency caps | Strict breakers |
| Deserialization | No weaponized gadgets | Controlled callbacks only |
| Prototype pollution | Isolated fixture state | Inert unique properties |
| Cache poisoning / smuggling | Lab-only Horizon deploy | No shared-infra tests |
| ReDoS / XML bomb | Bounded Lab ceilings | Else `manual_validation_required` |
| Mass assignment | Allowed vs unauthorized fields | Controlled accounts |

## Always

- Inventory every Horizon fixture
- Assign `passive_manual` or `unsupported` with exact missing capability
- Never silently exclude from the matrix
- Never inflate supported-active recall with passive/unsupported rows
