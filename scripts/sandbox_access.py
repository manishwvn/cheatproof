"""Free Nebius Sandboxes access check (no sandbox run, no spend).

Prints one line: ACCESS OK, NO ACCESS (<error class>) or ERROR (<error class>).
Exit 0 when access works, 2 when it is forbidden, 1 on any other failure.
Never prints the key, the project ID or raw error text.
"""

import sys

from cheatproof.envfile import load_env


def main() -> int:
    load_env()
    try:
        from contree_sdk import ContreeSync

        client = ContreeSync()
        client.get_token_info()
        list(client.images())
    except Exception as exc:  # noqa: BLE001 - only the class name is reported
        name = type(exc).__name__
        if name == "ForbiddenError":
            print(f"NO ACCESS ({name})")
            return 2
        print(f"ERROR ({name})")
        return 1
    print("ACCESS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
