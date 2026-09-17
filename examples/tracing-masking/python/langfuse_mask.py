"""The live Langfuse Python integration.

Langfuse Python's legacy `mask` hook receives the actual attribute value
(not a stringified form, unlike the JS SDK) and must return the masked
value:

    def masking_function(*, data: Any, **kwargs: Any) -> Any: ...

(https://langfuse.com/docs/observability/features/masking, confirmed
against the current docs while resolving issue #326.) `mask_secrets`
below matches that signature exactly, so it can be passed directly:

    from langfuse import Langfuse
    from langfuse_mask import mask_secrets

    langfuse = Langfuse(mask=mask_secrets)

Not imported by `test_mask_secrets.py` -- like
`examples/safe-integration`'s live wrapper files on the JS side, this thin
module is exercised against the real built package, not unit tested with
a fake. There is no init step for the Python bindings, unlike the JS
package's `await initialize()`.
"""

from __future__ import annotations

from typing import Any

import redact_secret

from mask_secrets import mask_secrets_with

__all__ = ["mask_secrets"]


def mask_secrets(*, data: Any, **_kwargs: Any) -> Any:
    return mask_secrets_with(redact_secret.scan_and_redact, data)
