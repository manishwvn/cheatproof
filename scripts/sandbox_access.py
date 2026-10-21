"""Free Nebius Sandboxes access check: one tiny run of `python -c "print('ok')"` in python:3.12-slim.

Prints one line: ACCESS OK, NO ACCESS (<error class> [HTTP status]), ERROR <error class> or
ERROR budget halted (402|cost).
Exit 0 when the run prints ok, 2 when the API refuses access (401/403), 1 on any other failure
after 5 tries (sleeps 2, 4, 8, 16 s between tries). Each invocation books one sandbox run in the budget.
A 402 halts the budget and exits 1 without retry. A reported run cost is logged in the ledger; a cost that takes
the logged Sandboxes sum past SANDBOX_COST_CAP_USD halts the budget and exits 1, also without retry.
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
PAYMENT_REQUIRED = 402


class UnexpectedOutput(Exception):
    """The probe ran but stdout had no `ok`. Only this class name is ever printed."""


def _default_client() -> Any:
    from contree_sdk import ContreeSync  # imported late: the env file is loaded before the SDK reads it

    return ContreeSync()


def _probe(client: Any) -> Any:
    # VERIFY: a tag-only image (no strict lookup) is resolved server side as "tag:<IMAGE>" on spawn.
    image = client.images.use(IMAGE)
    return image.run("python", args=["-c", "print('ok')"], disposable=True, timeout=RUN_TIMEOUT_S).wait()


def _status_of(exc: BaseException) -> int | None:
    status = getattr(exc, "status", None)  # ApiStatusCodeError and subclasses carry the HTTP status
    return status if isinstance(status, int) else None


def _is_auth_error(exc: BaseException) -> bool:
    return type(exc).__name__ == "ForbiddenError" or _status_of(exc) in AUTH_STATUSES


def _halt(budget: Budget, label: str) -> int:
    # Stops every paid call until a person clears the halt in the ledger. Never retried.
    try:
        budget.halt(f"sandbox access check: {label}")
    except Exception as exc:  # noqa: BLE001 - the halt was not written; only the class name is printed
        print(f"ERROR {type(exc).__name__}")
        return 1
    print(f"ERROR budget halted ({label})")
    return 1


def check_access(
    make_client: Callable[[], Any],
    budget: Budget,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    try:
        budget.reserve_sandbox_run()  # one run per invocation, booked before the first try
    except BudgetExceeded as exc:
        print(f"ERROR {type(exc).__name__}")  # a cap or halt stops the run; it is never retried
        return 1
    last: BaseException = UnexpectedOutput()
    for attempt in range(TRIES):
        try:
            done = _probe(make_client())
            # The SDK reports the run's cost on ContreeResult.cost (done.result), not on the finished image itself.
            cost = getattr(getattr(done, "result", None), "cost", None)
            if cost is not None:
                # Logged in the ledger. Raises (and the budget is halted) past the Sandboxes cost cap, or on a malformed
                # cost. Kept out of the retry loop below: a billed probe is never run again.
                try:
                    budget.book_sandbox_cost(cost)
                except BudgetExceeded:
                    print("ERROR budget halted (cost)")
                    return 1
                except Exception as exc:  # noqa: BLE001 - the cost was not logged; only the class name is printed
                    print(f"ERROR {type(exc).__name__}")
                    return 1
            if "ok" in str(done.stdout or ""):
                print("ACCESS OK")
                return 0
            last = UnexpectedOutput()
        except Exception as exc:  # noqa: BLE001 - only the class name and HTTP status are ever reported
            if _status_of(exc) == PAYMENT_REQUIRED:
                return _halt(budget, "402")
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
