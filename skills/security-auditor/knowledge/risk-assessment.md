# Risk Assessment Methodology

## Risk Formula
Risk = Likelihood × Impact

## Likelihood Scale
- 5 Almost Certain: exploited in the wild, trivial to execute
- 4 Likely: known exploit exists, attacker has motivation
- 3 Possible: some skill required, opportunistic
- 2 Unlikely: complex attack chain, limited attacker motivation
- 1 Rare: highly sophisticated, nation-state level

## Impact Scale
- 5 Critical: data breach affecting >100k records, full system compromise, regulatory shutdown
- 4 High: significant data loss, service outage >24h, regulatory fine likely
- 3 Medium: limited data exposure, service degradation, reputational damage
- 2 Low: minor data exposure, brief outage, low public impact
- 1 Informational: no direct impact, best-practice gap

## Risk Rating Matrix
| Likelihood \ Impact | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| 5 | Medium | High | Critical | Critical | Critical |
| 4 | Low | Medium | High | Critical | Critical |
| 3 | Low | Low | Medium | High | Critical |
| 2 | Info | Low | Low | Medium | High |
| 1 | Info | Info | Low | Low | Medium |

## Evidence Collection Checklist
- Access control: user access reviews, privileged account lists, MFA enforcement logs
- Vulnerability management: scan reports, patch SLAs, exception records
- Incident response: IR plan, tabletop exercise records, incident log
- Change management: change tickets, approval records, rollback procedures
- Vendor management: vendor inventory, BAAs/DPAs, vendor risk assessments
- Monitoring: SIEM alerts, log retention policy, alert response records
