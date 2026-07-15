## 2026-07-15 - Accessible Custom Toggles
**Learning:** Custom UI toggles implemented as `<div>` elements are completely inaccessible to keyboard users and screen readers, hiding important functionality from those users.
**Action:** Always use `<button type="button">` with `role="switch"` and dynamic `aria-checked` attributes for custom toggles. Ensure they have an `aria-label` and a `:focus-visible` CSS rule for keyboard navigation visibility.
