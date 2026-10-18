"""Hard spend cap shared by every paid call (LLM tokens and sandbox runs).

Token Factory has no documented hard spend limit and lets the balance go negative, so the cap
lives here. Every call reserves its worst-case cost before it runs and settles the real cost
after. A crash leaves the reservation counted, which errs on the side of spending less. The
ledger is a JSON file guarded by an OS file lock, so parallel processes share one budget.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path


class BudgetExceeded(RuntimeError):
    """A call would push spend past a cap, or the budget was halted."""


@dataclass(frozen=True)
class Price:
    input_per_m: float
    output_per_m: float

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_per_m + output_tokens * self.output_per_m) / 1_000_000


# The one total spend cap in USD (the account has about $25 of credits). Only the owner changes it.
DEFAULT_SPEND_CAP_USD = 20.0

# VERIFY: deliberately high until real Token Factory prices are recorded via MODEL_PRICES_JSON.
DEFAULT_PRICE = Price(input_per_m=3.0, output_per_m=10.0)


@dataclass(frozen=True)
class Hold:
    model: str
    usd: float
    day: str


def _ledger_path() -> Path:
    # One shared ledger for every checkout and worktree, so caps cannot multiply. Fail closed.
    raw = os.environ.get("SPEND_LEDGER", "")
    path = Path(raw).expanduser()
    if not raw or not path.is_absolute():
        raise BudgetExceeded("SPEND_LEDGER must be set to an absolute path (see .env.example)")
    return path


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
        self.ledger = Path(ledger)
        self.total_cap_usd = total_cap_usd
        self.daily_cap_usd = daily_cap_usd
        self.sandbox_run_cap = sandbox_run_cap
        # VERIFY: per-run sandbox price is not documented; this conservative guess counts toward the money caps.
        self.sandbox_run_usd = sandbox_run_usd
        self.prices = prices or {}
        self.default_price = default_price

    @classmethod
    def from_env(cls) -> Budget:
        raw = json.loads(os.environ.get("MODEL_PRICES_JSON", "{}"))
        prices = {model: Price(float(p[0]), float(p[1])) for model, p in raw.items()}
        return cls(
            ledger=_ledger_path(),
            total_cap_usd=float(os.environ.get("SPEND_CAP_USD", DEFAULT_SPEND_CAP_USD)),
            daily_cap_usd=float(os.environ.get("DAILY_CAP_USD", "4")),
            sandbox_run_cap=int(os.environ.get("SANDBOX_RUN_CAP", "250")),
            prices=prices,
            sandbox_run_usd=float(os.environ.get("SANDBOX_RUN_USD", "0.05")),
        )

    def price(self, model: str) -> Price:
        return self.prices.get(model, self.default_price)

    @contextmanager
    def _locked(self):
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger.with_suffix(".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self._read()
            yield state
            tmp = self.ledger.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
            os.replace(tmp, self.ledger)

    def _read(self) -> dict:
        if self.ledger.exists():
            return json.loads(self.ledger.read_text())
        return {"total_usd": 0.0, "days": {}, "sandbox_runs": 0, "halted": None}

    def reserve(self, model: str, input_tokens: int, max_output_tokens: int) -> Hold:
        return self._reserve_usd(model, self.price(model).cost(input_tokens, max_output_tokens))

    def _reserve_usd(self, model: str, worst: float) -> Hold:
        with self._locked() as s:
            return self._charge(s, model, worst)

    def _charge(self, s: dict, model: str, worst: float) -> Hold:
        # Caller holds the ledger lock, so the checks and the booking are one atomic step.
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
        actual = self.price(hold.model).cost(input_tokens, output_tokens)
        with self._locked() as s:
            delta = actual - hold.usd
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
        with self._locked() as s:
            s["halted"] = reason

    def snapshot(self) -> dict:
        with self._locked() as s:
            return dict(s)
