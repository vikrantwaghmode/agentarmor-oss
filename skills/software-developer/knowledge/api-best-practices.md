# API Design Best Practices

## REST
- Use nouns for resources: `/users`, `/orders/{id}` — not `/getUser`
- HTTP verbs: GET (read), POST (create), PUT (full replace), PATCH (partial update), DELETE
- Status codes: 200 OK, 201 Created, 204 No Content, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 422 Unprocessable Entity, 429 Too Many Requests, 500 Internal Error
- Versioning: URL prefix `/v1/`, or Accept header versioning
- Pagination: cursor-based preferred over offset for large datasets; return `next_cursor`
- Filtering: query params `?status=active&sort=-created_at` (minus = descending)

## Error Responses
```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Human-readable description",
    "details": [{"field": "email", "issue": "invalid format"}]
  }
}
```

## Security
- Always authenticate and authorise — never trust client-supplied IDs alone
- Rate limit all endpoints; return 429 with `Retry-After` header
- Validate and sanitise all inputs; never pass raw user input to DB or shell
- Use HTTPS only; set HSTS header
- Strip sensitive fields from responses (passwords, tokens, internal IDs)
- Implement idempotency keys for POST endpoints that trigger side effects

## Performance
- Use ETags and `Last-Modified` for caching
- Compress responses (gzip/brotli)
- Return only requested fields (`?fields=id,name`)
- Batch endpoints for bulk operations to reduce round trips
- Async for long operations: return 202 Accepted + `Location: /jobs/{id}`
