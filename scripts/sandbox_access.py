"""Free Nebius Sandboxes access check: one tiny run of `python -c "print('ok')"` in python:3.12-slim.

Prints one line: ACCESS OK, NO ACCESS (<error class> [HTTP status]) or ERROR <error class>.
Exit 0 when the run prints ok, 2 when the API refuses access (401/403), 1 on any other failure
after 5 tries (sleeps 2, 4, 8, 16 s between tries). Every try books one sandbox run in the budget.
Never prints the key, the project ID, IDs or raw error text: only exception class names and HTTP status codes.
"""

import sys
import time
from collections.abc import Callable
from typing import Any

from cheatproof.budget import Budget, BudgetExceeded
from cheatproof.envfile import load_env

IMAGE = "python:3.12-slim"
TRIES = 5
FIRST_DELAY_S = 2.0
RUN_TIMEOUT_S = 60
AUTH_STATUSES = frozenset({401, 403})


class UnexpectedOutput(Exception):
    """The probe ran but stdout had no `ok`. Only this class name is ever printed."""


def _default_client() -> Any:
    from contree_sdk import ContreeSync  # imported late: the env file is loaded before the SDK reads it

    return ContreeSync()


def _probe(client: Any) -> str:
    # VERIFY: a tag-only image (no strict lookup) is resolved server side as "tag:<IMAGE>" on spawn.
    image = client.images.use(IMAGE)
    done = image.run("python", args=["-c", "print('ok')"], disposable=True, timeout=RUN_TIMEOUT_S).wait()
    return str(done.stdout or "")


def _status_of(exc: BaseException) -> int | None:
    status = getattr(exc, "status", None)  # ApiStatusCodeError and subclasses carry the HTTP status
    return status if isinstance(status, int) else None


def _is_auth_error(exc: BaseException) -> bool:
    return type(exc).__name__ == "ForbiddenError" or _status_of(exc) in AUTH_STATUSES


def check_access(
    make_client: Callable[[], Any],
    budget: Budget,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    last: BaseException = UnexpectedOutput()
    for attempt in range(TRIES):
        try:
            budget.reserve_sandbox_run()  # cap check before any network call
            if "ok" in _probe(make_client()):
                print("ACCESS OK")
                return 0
            last = UnexpectedOutput()
        except BudgetExceeded as exc:
            print(f"ERROR {type(exc).__name__}")  # a cap or halt stops the run; it is never retried
            return 1
        except Exception as exc:  # noqa: BLE001 - only the class name and HTTP status are ever reported
            if _is_auth_error(exc):
                status = _status_of(exc)
                detail = type(exc).__name__ + (f" {status}" if status is not None else "")
                print(f"NO ACCESS ({detail})")
                return 2
            last = exc
        if attempt < TRIES - 1:
            sleep(FIRST_DELAY_S * 2**attempt)
    print(f"ERROR {type(last).__name__}")
    return 1


def main(
    make_client: Callable[[], Any] | None = None,
    budget: Budget | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    load_env()
    if budget is None:
        try:
            budget = Budget.from_env()
        except BudgetExceeded:
            print(f"ERROR {BudgetExceeded.__name__}")
            return 1
    return check_access(make_client or _default_client, budget, sleep)


if __name__ == "__main__":
    sys.exit(main())
