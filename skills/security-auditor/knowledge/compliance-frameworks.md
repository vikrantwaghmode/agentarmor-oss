# Compliance Framework Quick Reference

## SOC 2 Type II
- Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy
- Key controls: CC6 (logical access), CC7 (system operations), CC8 (change management)
- Evidence: access reviews, incident logs, change tickets, vendor assessments, penetration test reports
- Audit period: typically 12 months; Type II covers operating effectiveness over time

## ISO/IEC 27001:2022
- 93 controls across 4 themes: Organisational, People, Physical, Technological
- New in 2022: threat intelligence (5.7), cloud security (5.23), secure coding (8.28)
- Certification: external audit in two stages (documentation review + controls testing)
- Annual surveillance audits; full recertification every 3 years

## GDPR (EU 2016/679)
- Lawful bases: consent, contract, legal obligation, vital interests, public task, legitimate interest
- Key articles: 5 (principles), 6 (lawful basis), 13/14 (privacy notices), 17 (right to erasure), 25 (privacy by design), 32 (security of processing), 33/34 (breach notification)
- Breach notification: 72 hours to supervisory authority, without undue delay to data subjects
- DPO required for: public authorities, large-scale systematic monitoring, large-scale special category data

## HIPAA
- Safeguards: Administrative, Physical, Technical
- Key rules: Privacy Rule (PHI use/disclosure), Security Rule (ePHI protection), Breach Notification Rule
- Business Associate Agreements (BAA) required for vendors handling PHI
- Risk analysis: required annually, must document threats, vulnerabilities, and impact

## PCI-DSS v4.0
- 12 requirements: network security, cardholder data, vulnerability management, access control, monitoring, policies
- SAQ vs full QSA audit depends on transaction volume
- Network segmentation reduces scope; tokenisation removes card data from scope entirely
- New in v4.0: customised approach, multi-factor authentication expanded, targeted risk analysis
