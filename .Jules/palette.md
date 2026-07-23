## 2026-07-23 - Custom Toggle Switches Accessibility
**Learning:** Custom toggle switches in the frontend using `<div>` elements are not keyboard focusable or accessible to screen readers, violating a11y standards.
**Action:** Replaced `<div>` elements with `<button type="button">` elements, using `role="switch"`, `aria-checked`, and an accessible name (`aria-label`) to ensure accessibility.
