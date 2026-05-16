# Tenants

Each subdirectory is an isolated tenant. Create them from the dashboard
(Tenants tab, tab 08) or by hand:

```
tenants/
└── my-team/
    ├── tenant.yaml   # id, name, admin_token, user_token
    └── policy.yaml   # scanner config — inherits root policy.yaml on creation
```

## Routing a request to a tenant

Send either:
- `X-Tenant-ID: my-team` header, or
- the tenant's own Bearer token

The proxy routes to the matching tenant's isolated policy, sessions, and rate limits.
