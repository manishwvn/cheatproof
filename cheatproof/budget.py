"""Hard spend cap shared by every paid call (LLM tokens and sandbox runs).

Token Factory has no documented hard spend limit and lets the balance go negative, so the cap
lives here. Every call reserves its worst-case cost before it runs and settles the real cost
after. A crash leaves the reservation counted, which errs on the side of spending less. The
ledger is a JSON file guarded by an OS file lock, so parallel processes share one budget.

Fail closed. The total cap must be a finite number above 0 and at most MAX_TOTAL_CAP_USD. The
daily cap must be a finite number above 0 and at most the total cap. Every price must be a finite
number above 0, and the sandbox run cap a whole number of 0 or more. A missing, empty, nan, inf,
zero, negative or too-large money value, or a bad run cap, raises BudgetExceeded before anything
is spent, because a bad value must never read as "unlimited". A ledger that does not match this
shape is refused the same way, never repaired. snapshot() only reads the ledger and never writes it.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# Hard ceiling on the total cap, matching CLAUDE.md rule 1. Raising it needs a code change.
MAX_TOTAL_CAP_USD = 20.0


class BudgetExceeded(RuntimeError):
    """A call would push spend past a cap, the budget was halted, or a cap setting is missing or invalid."""


@dataclass(frozen=True)
class Price:
    input_per_m: float
    output_per_m: float

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_per_m + output_tokens * self.output_per_m) / 1_000_000


# VERIFY: deliberately high until real Token Factory prices are recorded via MODEL_PRICES_JSON.
DEFAULT_PRICE = Price(input_per_m=3.0, output_per_m=10.0)


@dataclass(frozen=True)
class Hold:
    model: str
    usd: float
    day: str


def _positive(name: str, value: object) -> float:
    """A finite number above 0, or BudgetExceeded. Zero or less would let spend through unchecked."""
    number = math.nan
    if not isinstance(value, bool):
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            pass
    if not math.isfinite(number) or number <= 0:
        raise BudgetExceeded(f"{name} must be a finite number above 0 (see .env.example), got {value!r}")
    return number


def _total_cap(value: object) -> float:
    number = _positive("total cap (SPEND_CAP_USD)", value)
    if number > MAX_TOTAL_CAP_USD:
        raise BudgetExceeded(
            f"total cap (SPEND_CAP_USD) must be at most ${MAX_TOTAL_CAP_USD:g} (see .env.example), got {value!r}"
        )
    return number


def _run_cap(value: object) -> int:
    # 0 is allowed: it means no sandbox runs, which spends nothing.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BudgetExceeded(
            f"sandbox_run_cap (SANDBOX_RUN_CAP) must be a whole number, 0 or more, got {value!r}"
        )
    return value


def _checked_price(label: str, price: Price) -> Price:
    return Price(
        input_per_m=_positive(f"{label} input price", price.input_per_m),
        output_per_m=_positive(f"{label} output price", price.output_per_m),
    )


def _is_spend(value: object) -> bool:
    """A finite number of 0 or more. Bools, strings, nan, inf and oversized ints are not spend."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def _tokens(name: str, value: object) -> int:
    # A whole number of tokens, 0 or more. Floats, bools and negatives are refused, never coerced.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BudgetExceeded(f"{name} must be a whole number of tokens, 0 or more, got {value!r}")
    return value


def _priced(price: Price, input_tokens: object, output_tokens: object) -> float:
    """The USD cost of a token count, or BudgetExceeded. Nothing that is not priceable gets booked."""
    tokens_in = _tokens("input tokens", input_tokens)
    tokens_out = _tokens("output tokens", output_tokens)
    try:
        cost = price.cost(tokens_in, tokens_out)
    except OverflowError:
        raise BudgetExceeded("token count is too large to price") from None
    if not _is_spend(cost):
        raise BudgetExceeded("cost is not a finite number of 0 or more")
    return cost


def _ledger_path() -> Path:
    # One shared ledger for every checkout and worktree, so caps cannot multiply. Fail closed.
    raw = os.environ.get("SPEND_LEDGER", "")
    path = Path(raw).expanduser()
    if not raw or not path.is_absolute():
        raise BudgetExceeded("SPEND_LEDGER must be set to an absolute path (see .env.example)")
    return path


def _env_cap(name: str) -> float:
    # Required: a missing money cap is never replaced by a default.
    if name not in os.environ:
        raise BudgetExceeded(f"{name} must be set to a finite number above 0 (see .env.example)")
    return _positive(name, os.environ[name])


def _env_prices() -> dict[str, Price]:
    raw = os.environ.get("MODEL_PRICES_JSON", "{}")
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise BudgetExceeded("MODEL_PRICES_JSON is not valid JSON (see .env.example)") from None
    if not isinstance(parsed, dict):
        raise BudgetExceeded("MODEL_PRICES_JSON must map model ids to [input, output] USD per 1M tokens")
    prices: dict[str, Price] = {}
    for model, pair in parsed.items():
        if not isinstance(pair, list) or len(pair) != 2:
            raise BudgetExceeded(f"MODEL_PRICES_JSON entry for {model} must be [input, output]")
        prices[model] = Price(pair[0], pair[1])  # the Budget constructor checks each number
    return prices


class Budget:
    def __init__(
        self,
        ledger: Path,
        total_cap_usd: float,
        daily_cap_usd: float,
        sandbox_run_cap: int,
        prices: dict[str, Price] | None = None,
        sandbox_run_usd: float = 0.05,
        default_price: Price = DEFAULT_PRICE,
    ) -> None:
        # Every cap and price is checked here too, so a direct construction fails closed as well.
        self.ledger = Path(ledger)
        self.total_cap_usd = _total_cap(total_cap_usd)
        self.daily_cap_usd = _positive("daily cap (DAILY_CAP_USD)", daily_cap_usd)
        if self.daily_cap_usd > self.total_cap_usd:
            raise BudgetExceeded(
                f"daily cap (DAILY_CAP_USD) ${self.daily_cap_usd:g} must not exceed "
                f"the total cap (SPEND_CAP_USD) ${self.total_cap_usd:g}"
            )
        self.sandbox_run_cap = _run_cap(sandbox_run_cap)
        # VERIFY: per-run sandbox price is not documented; this conservative guess counts toward the money caps.
        self.sandbox_run_usd = _positive("sandbox run price (SANDBOX_RUN_USD)", sandbox_run_usd)
        self.prices = {model: _checked_price(f"price for {model}", p) for model, p in (prices or {}).items()}
        self.default_price = _checked_price("default price", default_price)

    @classmethod
    def from_env(cls) -> Budget:
        # The ledger is checked first, then the two money caps, which have no defaults.
        ledger = _ledger_path()
        total_cap = _env_cap("SPEND_CAP_USD")
        daily_cap = _env_cap("DAILY_CAP_USD")
        raw_run_cap = os.environ.get("SANDBOX_RUN_CAP", "250")
        try:
            run_cap = int(raw_run_cap)
        except (ValueError, OverflowError):
            raise BudgetExceeded(
                f"SANDBOX_RUN_CAP must be a whole number, 0 or more, got {raw_run_cap!r}"
            ) from None
        return cls(
            ledger=ledger,
            total_cap_usd=total_cap,
            daily_cap_usd=daily_cap,
            sandbox_run_cap=run_cap,
            prices=_env_prices(),
            sandbox_run_usd=_positive("SANDBOX_RUN_USD", os.environ.get("SANDBOX_RUN_USD", "0.05")),
        )

    def price(self, model: str) -> Price:
        return self.prices.get(model, self.default_price)

    @contextmanager
    def _lock(self):
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        # Append mode creates the lock file without truncating it.
        with open(self.ledger.with_suffix(".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @contextmanager
    def _locked(self):
        # The state is written back only when the block exits normally, so a refused call changes nothing.
        with self._lock():
            state = self._read()
            yield state
            tmp = self.ledger.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
            os.replace(tmp, self.ledger)

    def _read(self) -> dict:
        if not self.ledger.exists():
            return {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}
        try:
            state = json.loads(self.ledger.read_text())
        except ValueError:
            raise BudgetExceeded(f"ledger {self.ledger} is not valid JSON; fix it by hand") from None
        if not isinstance(state, dict) or not all(k in state for k in ("total_usd", "days", "sandbox_runs")):
            # A missing field would read as zero spend or zero runs, which would loosen a cap. Refuse instead.
            raise BudgetExceeded(
                f"ledger {self.ledger} must hold total_usd, days and sandbox_runs; fix it by hand"
            )
        days = state["days"]
        if not isinstance(days, dict):
            raise BudgetExceeded(
                f"ledger {self.ledger} has a days field that is not an object; fix it by hand"
            )
        amounts = [state["total_usd"], *days.values()]
        if not all(_is_spend(amount) for amount in amounts):
            # A nan or negative amount would make every cap comparison pass. Refuse instead.
            raise BudgetExceeded(f"ledger {self.ledger} has a non-finite or negative amount; fix it by hand")
        runs = state["sandbox_runs"]
        if isinstance(runs, bool) or not isinstance(runs, int) or runs < 0:
            raise BudgetExceeded(
                f"ledger {self.ledger} has sandbox_runs that is not a whole number, 0 or more; fix it by hand"
            )
        # Stored as None (not halted), a bool, or a non-empty string. An empty string would read as not halted.
        halted = state.get("halted")
        if halted is not None and not isinstance(halted, bool) and not (isinstance(halted, str) and halted):
            raise BudgetExceeded(f"ledger {self.ledger} has an invalid halted value; fix it by hand")
        return state

    def reserve(self, model: str, input_tokens: int, max_output_tokens: int) -> Hold:
        return self._reserve_usd(model, _priced(self.price(model), input_tokens, max_output_tokens))

    def _reserve_usd(self, model: str, worst: float) -> Hold:
        with self._locked() as s:
            return self._charge(s, model, worst)

    def _charge(self, s: dict, model: str, worst: float) -> Hold:
        # Caller holds the ledger lock, so the checks and the booking are one atomic step.
        if not _is_spend(worst):
            raise BudgetExceeded(f"reserved amount must be a finite number of 0 or more, got {worst!r}")
        day = date.today().isoformat()
        if s["halted"]:
            raise BudgetExceeded(f"budget halted: {s['halted']}")
        if s["total_usd"] + worst > self.total_cap_usd:
            raise BudgetExceeded(f"total cap ${self.total_cap_usd:.2f} reached (spent ${s['total_usd']:.4f})")
        today = s["days"].get(day, 0.0)
        if today + worst > self.daily_cap_usd:
            raise BudgetExceeded(f"daily cap ${self.daily_cap_usd:.2f} reached (today ${today:.4f})")
        s["total_usd"] += worst
        s["days"][day] = today + worst
        return Hold(model, worst, day)

    def settle(self, hold: Hold, input_tokens: int, output_tokens: int) -> float:
        # Bad input raises before the lock is taken, so the hold stays booked at its full amount.
        if not _is_spend(hold.usd):
            raise BudgetExceeded("hold amount must be a finite number of 0 or more")
        actual = _priced(self.price(hold.model), input_tokens, output_tokens)
        with self._locked() as s:
            # A refund is never larger than the hold, and a booked amount never drops below zero.
            delta = max(actual - hold.usd, -hold.usd)
            s["total_usd"] = max(0.0, s["total_usd"] + delta)
            s["days"][hold.day] = max(0.0, s["days"].get(hold.day, 0.0) + delta)
        return actual

    def reserve_sandbox_run(self) -> Hold:
        # One lock for the run cap, the money caps, the halt flag and both counters, so parallel
        # processes cannot all pass the checks and then overshoot. The run's cost stays booked.
        with self._locked() as s:
            if s["halted"]:
                raise BudgetExceeded(f"budget halted: {s['halted']}")
            if s["sandbox_runs"] >= self.sandbox_run_cap:
                raise BudgetExceeded(f"sandbox run cap {self.sandbox_run_cap} reached")
            hold = self._charge(s, "sandbox-run", self.sandbox_run_usd)
            s["sandbox_runs"] += 1
        return hold

    def halt(self, reason: str) -> None:
        """Stop all paid calls until a person clears `halted` in the ledger file."""
        # An empty or non-text reason would read as not halted, so it is stored as a fixed non-empty text.
        text = reason if isinstance(reason, str) and reason.strip() else "halted"
        with self._locked() as s:
            s["halted"] = text

    def snapshot(self) -> dict:
        """Read-only view of the ledger. It never writes, creates or resets a field.

        A cleared `halted` flag therefore stays cleared.
        """
        lock_path = self.ledger.with_suffix(".lock")
        if not lock_path.exists():
            # No writer has ever locked this ledger, so there is nothing to wait for.
            return self._read()
        with open(lock_path) as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            return self._read()
