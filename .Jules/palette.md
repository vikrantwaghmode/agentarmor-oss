## 2024-05-24 - Accessibility for Toggle Switches
**Learning:** Custom toggle switches implemented as `<div>` elements are not keyboard focusable and do not correctly broadcast their state to screen readers.
**Action:** Use `<button type="button" role="switch" aria-checked={...}>` instead of `<div>` for all custom `.sq-toggle` elements. Ensure they can be activated via space/enter keys.
