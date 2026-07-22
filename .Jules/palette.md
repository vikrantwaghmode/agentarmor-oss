## 2024-05-24 - Accessibility pattern for .sq-toggle switches
**Learning:** The custom `.sq-toggle` switches in this app were originally implemented as `<div>` elements, which are not keyboard focusable and lack semantic meaning for screen readers, making them inaccessible.
**Action:** Always use `<button type="button" role="switch" aria-checked={...} aria-label="...">` instead of `<div>` for `.sq-toggle` elements to ensure keyboard focusability and screen reader support.
