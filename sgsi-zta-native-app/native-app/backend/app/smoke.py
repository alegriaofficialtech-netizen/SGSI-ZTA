"""Native smoke follows current private/public M2 configuration."""

import sys

from app.config import get_settings
from app.mfa_smoke import main

if __name__ == "__main__":
    public = next(
        (
            url
            for url in get_settings().allowed_origins
            if url.startswith("https://") and url.endswith(".trycloudflare.com")
        ),
        None,
    )
    if public:
        sys.argv += ["--url", public, "--phase", "public"]
    main()
