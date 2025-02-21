---
"@animo-id/mdoc": patch
---

fix: update context interface to not allow random callback to be async

The current code did not await the callback, and thus did not support async random generation. In a future (breaking) change we might update the code to support async random byte generation, but most random byte generators in JavaScript are sync. If you depend on an async random byte generator, please open an issue.
