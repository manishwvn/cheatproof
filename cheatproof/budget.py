"""Hard spend cap shared by every paid call (LLM tokens).

Token Factory has no documented hard spend limit and lets the balance go negative, so the cap
lives here. Every call reserves its worst-case cost before it runs and settles the real cost
after. A crash leaves the reservation counted, which errs on the side of spending less. The
ledger is a JSON file guarded by an OS file lock, so parallel processes share one budget.

Fail closed. The total cap must be a finite number above 0 and at most MAX_TOTAL_CAP_USD. The
daily cap must be a finite number above 0 and at most the total cap. Every price must be a finite
number above 0, and the sandbox, local and Tavily call caps whole numbers of 0 or more. A missing,
empty, nan, inf, zero, negative or too-large money value, or a bad count cap, raises BudgetExceeded
before anything is spent, because a bad value must never read as "unlimited". Sandboxes runs count
against SANDBOX_RUN_CAP. Each cost a Sandboxes result reports is logged in the ledger's Sandboxes section,
never in the Token Factory totals, and the budget halts once the logged sum passes SANDBOX_COST_CAP_USD.
The trial cap (TRIAL_CREDIT_CAP_USD) limits Token Factory spend counted from when it is set. Local Docker
runs and Tavily calls book no money; they only count against their caps. A ledger that does not match
this shape is refused the same way, never repaired. A missing ledger is refused too: only create_ledger (the
`budget init` CLI command) creates one, so a run never starts on a ledger nobody made. snapshot() only reads the
ledger and never writes it.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# Hard ceiling on the total cap, matching CLAUDE.md rule 1. Raising it needs a code change.
MAX_TOTAL_CAP_USD = 20.0
# Cap on the summed Sandboxes cost in the ledger. An invalid SANDBOX_COST_CAP_USD falls back to this, never to no cap.
DEFAULT_SANDBOX_COST_CAP_USD = 0.50
# Cap on Token Factory spend counted from when it is set: $0.84 of trial credit left, minus a $0.10 floor.
DEFAULT_TRIAL_CREDIT_CAP_USD = 0.74


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


def _count_cap(label: str, value: object) -> int:
    # 0 is allowed: it means no runs or calls of this kind, which spends nothing.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BudgetExceeded(f"{label} must be a whole number, 0 or more, got {value!r}")
    return value


def _count_env(name: str, default: str) -> int:
    raw = os.environ.get(name, default)
    try:
        return int(raw)
    except (ValueError, OverflowError):
        raise BudgetExceeded(f"{name} must be a whole number, 0 or more, got {raw!r}") from None


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


def _sandbox_cost_cap_env() -> float:
    # Missing, invalid or above the ceiling: the default. Any valid value is used, including a stricter one.
    try:
        value = _positive("SANDBOX_COST_CAP_USD", os.environ.get("SANDBOX_COST_CAP_USD", ""))
    except BudgetExceeded:
        return DEFAULT_SANDBOX_COST_CAP_USD
    return value if value <= MAX_TOTAL_CAP_USD else DEFAULT_SANDBOX_COST_CAP_USD


def _trial_cap_env() -> float:
    # Unset means the default. Set but invalid raises: a bad trial cap never reads as unlimited.
    if "TRIAL_CREDIT_CAP_USD" not in os.environ:
        return DEFAULT_TRIAL_CREDIT_CAP_USD
    raw = os.environ["TRIAL_CREDIT_CAP_USD"]
    value = _positive("TRIAL_CREDIT_CAP_USD", raw)
    if value > MAX_TOTAL_CAP_USD:
        raise BudgetExceeded(
            f"TRIAL_CREDIT_CAP_USD must be at most ${MAX_TOTAL_CAP_USD:g} (see .env.example), got {raw!r}"
        )
    return value


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


def fresh_ledger() -> dict:
    """A zeroed ledger with every field the reader expects. Only create_ledger writes one."""
    return {
        "total_usd": 0.0,
        "days": {},
        "sandbox_runs": 0,
        "local_runs": 0,
        "tavily_calls": 0,
        "halted": None,
        "sandbox_cost_usd": 0.0,
        "sandbox_cost_days": {},
        "trial_spend_usd": 0.0,
    }


def create_ledger(path: Path) -> Path:
    """Create the zeroed ledger at path, the only way a ledger comes into being. An existing file is refused, never
    overwritten. The ledger lock is held, so a concurrent writer cannot slip in between the check and the create."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_suffix(".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            raise BudgetExceeded(f"ledger {path} already exists; refusing to overwrite it")
        with open(path, "x") as f:
            f.write(json.dumps(fresh_ledger(), indent=2, sort_keys=True))
    return path


def init_ledger_from_env() -> Path:
    """Create the zeroed ledger at SPEND_LEDGER (see create_ledger). Fails closed when SPEND_LEDGER is unset or relative."""
    return create_ledger(_ledger_path())


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
        local_run_cap: int = 2000,
        tavily_call_cap: int = 200,
        sandbox_cost_cap_usd: float = DEFAULT_SANDBOX_COST_CAP_USD,
        trial_credit_cap_usd: float = DEFAULT_TRIAL_CREDIT_CAP_USD,
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
        self.sandbox_run_cap = _count_cap("sandbox_run_cap (SANDBOX_RUN_CAP)", sandbox_run_cap)
        # Parsed and checked so SANDBOX_RUN_USD fails closed. Never charged: no Token Factory money moves for a run.
        self.sandbox_run_usd = _positive("sandbox run price (SANDBOX_RUN_USD)", sandbox_run_usd)
        self.prices = {model: _checked_price(f"price for {model}", p) for model, p in (prices or {}).items()}
        self.default_price = _checked_price("default price", default_price)
        # Count-only caps: local Docker and Tavily book $0, so they never touch the money caps.
        self.local_run_cap = _count_cap("local_run_cap (LOCAL_RUN_CAP)", local_run_cap)
        self.tavily_call_cap = _count_cap("tavily_call_cap (TAVILY_CALL_CAP)", tavily_call_cap)
        self.sandbox_cost_cap_usd = _positive("sandbox cost cap (SANDBOX_COST_CAP_USD)", sandbox_cost_cap_usd)
        self.trial_credit_cap_usd = _positive("trial credit cap (TRIAL_CREDIT_CAP_USD)", trial_credit_cap_usd)

    @classmethod
    def from_env(cls) -> Budget:
        # The ledger is checked first, then the two money caps, which have no defaults, then the optional caps.
        ledger = _ledger_path()
        total_cap = _env_cap("SPEND_CAP_USD")
        daily_cap = _env_cap("DAILY_CAP_USD")
        trial_cap = _trial_cap_env()
        run_cap = _count_env("SANDBOX_RUN_CAP", "250")
        local_cap = _count_env("LOCAL_RUN_CAP", "2000")
        tavily_cap = _count_env("TAVILY_CALL_CAP", "200")
        return cls(
            ledger=ledger,
            total_cap_usd=total_cap,
            daily_cap_usd=daily_cap,
            sandbox_run_cap=run_cap,
            prices=_env_prices(),
            sandbox_run_usd=_positive("SANDBOX_RUN_USD", os.environ.get("SANDBOX_RUN_USD", "0.05")),
            local_run_cap=local_cap,
            tavily_call_cap=tavily_cap,
            sandbox_cost_cap_usd=_sandbox_cost_cap_env(),
            trial_credit_cap_usd=trial_cap,
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
            # Never created implicitly: a missing ledger would read as zero spend and let a run start unbooked.
            raise BudgetExceeded(
                f"ledger {self.ledger} does not exist; run `python -m cheatproof.cli budget init` once to create it"
            )
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
        # Optional: ledgers written before these counters existed lack them, and that reads as 0.
        for key in ("local_runs", "tavily_calls"):
            if key in state:
                count = state[key]
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise BudgetExceeded(
                        f"ledger {self.ledger} has {key} that is not a whole number, 0 or more; "
                        "fix it by hand"
                    )
        # Optional, added with the Sandboxes cost log and the trial cap: a missing key reads as 0.
        for key in ("sandbox_cost_usd", "trial_spend_usd"):
            if key in state and not _is_spend(state[key]):
                raise BudgetExceeded(f"ledger {self.ledger} has {key} that is not a finite number, 0 or more")
        cost_days = state.get("sandbox_cost_days", {})
        if not isinstance(cost_days, dict) or not all(_is_spend(amount) for amount in cost_days.values()):
            raise BudgetExceeded(
                f"ledger {self.ledger} has a sandbox_cost_days field that is not a map of amounts"
            )
        # Stored as None (not halted), a bool, or a non-empty string. An empty string would read as not halted.
        halted = state.get("halted")
        if halted is not None and not isinstance(halted, bool) and not (isinstance(halted, str) and halted):
            raise BudgetExceeded(f"ledger {self.ledger} has an invalid halted value; fix it by hand")
        return state

    def check_not_halted(self) -> None:
        """Refuse while the ledger says halted. Read-only. Called before every exec, paid or free, so a halt stops the next one."""
        halted = self.snapshot().get("halted")
        if halted:
            raise BudgetExceeded(f"budget halted: {halted}")

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
        trial = s.get("trial_spend_usd", 0.0)
        if trial + worst > self.trial_credit_cap_usd:
            raise BudgetExceeded(
                f"trial credit cap (TRIAL_CREDIT_CAP_USD) ${self.trial_credit_cap_usd:.2f} reached "
                f"(${trial:.4f} counted since the cap was set)"
            )
        s["total_usd"] += worst
        s["days"][day] = today + worst
        s["trial_spend_usd"] = trial + worst
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
            s["trial_spend_usd"] = max(0.0, s.get("trial_spend_usd", 0.0) + delta)
        return actual

    def reserve_sandbox_run(self) -> None:
        """Count one Sandboxes run against sandbox_run_cap. Refused while the logged Sandboxes cost is over its cap."""
        self._reserve_count("sandbox_runs", self.sandbox_run_cap, "sandbox run cap", self._check_sandbox_cost)

    def _check_sandbox_cost(self, s: dict) -> None:
        logged = s.get("sandbox_cost_usd", 0.0)
        if logged > self.sandbox_cost_cap_usd:
            raise BudgetExceeded(
                f"sandbox cost cap ${self.sandbox_cost_cap_usd:.2f} reached (logged ${logged:.4f})"
            )

    def reserve_local_run(self) -> None:
        """Count one local Docker run against local_run_cap. Free: books no money."""
        self._reserve_count("local_runs", self.local_run_cap, "local run cap")

    def reserve_tavily_call(self) -> None:
        """Count one Tavily search call against tavily_call_cap. Free credits: books no money."""
        self._reserve_count("tavily_calls", self.tavily_call_cap, "tavily call cap")

    def _reserve_count(
        self, key: str, cap: int, label: str, check: Callable[[dict], None] | None = None
    ) -> None:
        # One lock for the halt flag, the cap check and the increment, so parallel callers cannot overshoot.
        # A missing key is an old ledger and counts as 0. A refused call writes nothing.
        with self._locked() as s:
            halted = s.get("halted")
            if halted:
                raise BudgetExceeded(f"budget halted: {halted}")
            if check is not None:
                check(s)
            used = s.get(key, 0)
            if used >= cap:
                raise BudgetExceeded(f"{label} {cap} reached")
            s[key] = used + 1

    def halt(self, reason: str) -> None:
        """Stop all paid calls until a person clears `halted` in the ledger file."""
        # An empty or non-text reason would read as not halted, so it is stored as a fixed non-empty text.
        text = reason if isinstance(reason, str) and reason.strip() else "halted"
        with self._locked() as s:
            s["halted"] = text

    def book_sandbox_cost(self, usd: object) -> None:
        """Log one cost that a Sandboxes result reported, in the ledger's Sandboxes section (never the Token Factory
        totals). The budget halts once the logged sum passes sandbox_cost_cap_usd. A malformed cost halts at once,
        since it cannot be counted. A call that finds the budget already halted still raises, so it stops."""
        if not _is_spend(usd):
            self.halt("a Sandboxes result reported a cost that is not a finite number of 0 or more")
            raise BudgetExceeded("a Sandboxes result reported a malformed cost; the budget is halted")
        if usd == 0:
            self.check_not_halted()  # a free result writes nothing, but a halted budget still stops here
            return  # a free result changes nothing, so nothing is written
        day = date.today().isoformat()
        with self._locked() as s:
            was_halted = bool(s.get("halted"))
            logged = s.get("sandbox_cost_usd", 0.0) + usd
            s["sandbox_cost_usd"] = logged
            cost_days = s.setdefault("sandbox_cost_days", {})
            cost_days[day] = cost_days.get(day, 0.0) + usd
            over = logged > self.sandbox_cost_cap_usd
            if over and not was_halted:
                s["halted"] = (
                    f"Sandboxes cost ${logged:.4f} is above the ${self.sandbox_cost_cap_usd:.2f} cap"
                )
        # Raised after the block, so the ledger write above has already happened: the cost stays logged.
        if over:
            raise BudgetExceeded(
                f"Sandboxes cost ${logged:.4f} is above the ${self.sandbox_cost_cap_usd:.2f} cap; the budget is halted"
            )
        if was_halted:
            raise BudgetExceeded("a Sandboxes result reported a cost while the budget is halted")

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
