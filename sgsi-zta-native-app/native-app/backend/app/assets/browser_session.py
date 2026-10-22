"""Machine-only QA bridge. Invoke via captured SSH stdout, never interactive logs.

Passwords and TOTP stay inside the backend. Session cookies travel only in memory
to the authorized QA browser; they must be revoked at the end of the test.
"""

import argparse
import json

from app.assets.acceptance import authenticated_client, deployed_url


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("username", choices=["admin.demo", "auditor.demo"])
    args = parser.parse_args()
    url = deployed_url()
    assert url.startswith("https://"), "QA bridge requires public HTTPS"
    with authenticated_client(args.username, url, logout=False) as client:
        print(
            json.dumps(
                {
                    "url": url,
                    "csrf": client.headers["X-CSRF-Token"],
                    "cookies": [
                        {
                            "name": cookie.name,
                            "value": cookie.value,
                            "domain": cookie.domain,
                            "path": cookie.path,
                            "secure": cookie.secure,
                            "httpOnly": cookie.name != "sgsi_csrf",
                            "sameSite": "Strict",
                        }
                        for cookie in client.cookies.jar
                    ],
                }
            )
        )


if __name__ == "__main__":
    main()
