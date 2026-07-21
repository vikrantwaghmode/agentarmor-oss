## 2024-05-14 - Semantic Toggles for Better Accessibility
**Learning:** Custom interactive elements, like custom toggle switches previously built using `<div>` tags, lack native semantic roles, making them inaccessible to screen readers and difficult to navigate via keyboard.
**Action:** Always use `<button type="button" role="switch" aria-checked={...}>` rather than a generic `<div>` for custom toggles to ensure proper semantic meaning, ARIA state communication, and keyboard focusability without needing extensive manual ARIA role or event handling.
