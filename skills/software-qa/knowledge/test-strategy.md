# Test Strategy Reference

## Testing Pyramid
- **Unit** (base, many): isolated, fast, deterministic — mock all external deps
- **Integration** (middle, moderate): real deps, real DB, no UI — test component boundaries
- **E2E** (top, few): full stack from UI to DB — cover happy path + critical flows only

## Test Types
| Type | What it validates | Tools |
|---|---|---|
| Unit | Single function/class logic | Jest, pytest, JUnit, Go test |
| Integration | Service + DB + queue interactions | Testcontainers, real Docker services |
| Contract | API shape between services | Pact, Dredd |
| E2E | Full user journey | Playwright, Cypress, Selenium |
| Performance | Throughput, latency, load | k6, Locust, JMeter |
| Security | Injection, auth, OWASP issues | OWASP ZAP, Burp, sqlmap |
| Accessibility | WCAG compliance | axe-core, Lighthouse |

## Test Case Design Techniques
- **Equivalence partitioning**: group inputs into valid/invalid classes; test one per class
- **Boundary value analysis**: test min, max, min-1, max+1 for numeric/string ranges
- **Decision table**: all combinations of conditions → actions
- **State transition**: test each valid and invalid transition in a state machine
- **Exploratory testing**: charter-based, time-boxed; log observations, file bugs immediately

## Acceptance Criteria Format (Given/When/Then)
```
Given [precondition / starting state]
When  [action / event]
Then  [expected outcome]
```

## Definition of Done (checklist)
- [ ] All acceptance criteria pass
- [ ] Unit tests written and passing (coverage ≥ threshold)
- [ ] Integration tests cover new endpoints / data flows
- [ ] No new critical/high bugs open
- [ ] Performance impact assessed
- [ ] Accessibility checked if UI changed
- [ ] Security implications reviewed
- [ ] Release notes updated
