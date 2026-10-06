"""Flat-YAML policy: default-deny allowlist, per-(tool, environment) risk tier,
output cap, blast radius, flat `where` conditions on argument values. No DSL."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .store import USAGE_RETENTION_S, MemoryStore

Tier = Literal["L0", "L1", "L2", "L3"]
GROUP_PREFIX = "group:"  # a `principals` key for a group; never matched against the caller's own name
# L0 read:     pass through
# L1 suggest:  write tool, always forced dry_run=true (never executes)
# L2 confirm:  dry_run=true until a human confirms via MRTR, then executes once
# L3 auto:     executes without confirmation


class OutputCap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_chars: int = 16_000
    chars_per_token: float = Field(4.0, gt=0)  # crude estimate; good enough for a cap


class BlastRadius(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_per_call: int = 50
    max_per_principal: int = 500
    window_s: int = Field(3600, ge=1, le=USAGE_RETENTION_S)  # the store keeps usage rows for one day


class WhereRule(BaseModel):
    """One condition on one argument value. Exactly one matcher."""
    model_config = ConfigDict(extra="forbid")
    arg: str
    equals: Any = None  # `equals: null` is a real matcher: "given" is what model_fields_set says, not the value
    in_: list[Any] | None = Field(None, alias="in")  # `in` is a Python keyword
    not_in: list[Any] | None = None
    regex: str | None = None  # full match, strings only
    env: list[str] | None = None  # None = every environment
    optional: bool = False  # an absent argument passes

    @model_validator(mode="after")
    def _one_matcher(self) -> WhereRule:
        given = ["equals" in self.model_fields_set, self.in_ is not None, self.not_in is not None, self.regex is not None]
        if sum(given) != 1:
            raise ValueError("exactly one of equals, in, not_in, regex is required")
        for name, values in (("in", self.in_), ("not_in", self.not_in), ("env", self.env)):
            if values is not None and not values:
                raise ValueError(f"{name} must not be empty")  # in/not_in: [] denies every value; env: [] applies nowhere
        listed = [self.equals] if "equals" in self.model_fields_set else self.in_ if self.in_ is not None else self.not_in
        if listed is not None and not all(x is None or isinstance(x, (str, int, float, bool)) for x in listed):
            raise ValueError("equals/in/not_in values must be scalars")  # a list or dict element can never match
        if self.regex is not None:
            try:
                re.compile(self.regex)  # an invalid pattern is a load error, not a runtime one
            except re.error as e:
                raise ValueError(f"invalid regex: {e}") from e
        return self

    def kind(self) -> str:
        return ("equals" if "equals" in self.model_fields_set else "in" if self.in_ is not None
                else "not_in" if self.not_in is not None else "regex")

    def holds(self, v: Any) -> bool:
        """The whole argument value: every element of a list must match (an empty list passes), a scalar must match."""
        if isinstance(v, (list, tuple)):
            return all(self.matches(x) for x in v)
        if isinstance(v, str) and not isinstance(_json(v), str):
            return False  # the upstream SDK json-decodes it (top level only) into a null, list or dict the policy never saw, or cannot decode here
        return self.matches(v)

    def matches(self, v: Any) -> bool:
        """One scalar value. A null matches only `equals: null`; anything else that is not a str, int, float or bool fails (closed)."""
        if v is None:
            return self.kind() == "equals" and self.equals is None
        if not isinstance(v, (str, int, float, bool)):
            return False
        if self.regex is not None:
            return isinstance(v, str) and re.fullmatch(self.regex, v) is not None
        if self.kind() == "equals":
            return _same(v, self.equals)
        if self.in_ is not None:
            return any(_same(v, x) for x in self.in_)
        # not_in is a deny list, and the upstream reads "0" and False as 0 and "yes" as True for an int or bool argument:
        # a value of a kind the list does not contain fails too, instead of passing as "not listed"
        return any(_kind(v) == _kind(x) for x in self.not_in) and not any(_same(v, x) for x in self.not_in)


def _same(a: Any, b: Any) -> bool:
    return isinstance(a, bool) == isinstance(b, bool) and a == b  # True is not 1


def _kind(x: Any) -> type:
    return bool if isinstance(x, bool) else float if isinstance(x, (int, float)) else type(x)  # int and float are one kind


_UNDECODABLE = object()  # json.loads gave up on a limit of this interpreter, which the upstream's may not share


def _json(s: str) -> Any:
    """What the upstream SDK would substitute for the string, or the string itself when it leaves it alone.
    _UNDECODABLE when a list or object failed to decode on nesting depth or integer size: those limits differ per
    Python version, frame depth and PYTHONINTMAXSTRDIGITS, so the upstream may still read what the policy could not."""
    try:
        d = json.loads(s)
    except json.JSONDecodeError:
        return s  # not JSON on any interpreter
    except (ValueError, RecursionError):  # the integer digit limit raises a plain ValueError
        # a bare number stays a string upstream whether its decode fails there too or yields an int the SDK keeps
        return _UNDECODABLE if s.lstrip().startswith(("[", "{")) else s
    return s if isinstance(d, (str, int, float)) else d  # the SDK keeps a decoded str, int or float (a bool is an int)


_WHY = {"equals": "does not equal the required value", "in": "is not in the allowed values",
        "not_in": "is in the forbidden values", "regex": "does not match the required pattern"}


class ToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tiers: dict[str, Tier]  # environment -> tier; no entry for the running env = deny
    principals: dict[str, dict[str, Tier]] = Field(default_factory=dict)  # "alice" or "group:oncall" -> env -> tier
    description: str = ""
    count_arg: str | None = None  # list-valued argument whose length is the object count
    output: OutputCap | None = None
    blast_radius: BlastRadius | None = None
    where: list[WhereRule] = Field(default_factory=list)  # all applicable rules must hold


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = 1
    environment: str
    output: OutputCap = Field(default_factory=OutputCap)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    tools: dict[str, ToolRule] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path, environment: str | None = None) -> Policy:
        data = yaml.safe_load(Path(path).read_text()) or {}
        if environment:
            data["environment"] = environment
        return cls.model_validate(data)

    def tier(self, tool: str, principal: str | None = None, groups: tuple[str, ...] | list[str] = ()) -> Tier | None:
        rule = self.tools.get(tool)
        if rule is None:
            return None
        # principal beats group, first group wins. "group:" keys are groups only: a subject that happens to be
        # named "group:oncall" must not inherit the group's tier.
        own = [principal] if principal and not principal.startswith(GROUP_PREFIX) else []
        for key in own + [f"{GROUP_PREFIX}{g}" for g in groups]:
            override = rule.principals.get(key, {})
            if self.environment in override:
                return override[self.environment]
        return rule.tiers.get(self.environment)

    def output_cap(self, tool: str) -> OutputCap:
        rule = self.tools.get(tool)
        return rule.output if rule and rule.output else self.output

    def blast(self, tool: str) -> BlastRadius:
        rule = self.tools.get(tool)
        return rule.blast_radius if rule and rule.blast_radius else self.blast_radius

    def args_violation(self, tool: str, args: dict[str, Any]) -> str | None:
        """Message for the first failing `where` rule that applies in this environment, None if all hold.
        Names the argument and the matcher, never the value."""
        rule = self.tools.get(tool)
        for w in rule.where if rule else ():
            if w.env is not None and self.environment not in w.env:
                continue
            if w.arg not in args:
                if w.optional:
                    continue
                return f"argument {w.arg!r} is missing, required by the {w.kind()} condition"
            if not w.holds(args[w.arg]):
                return f"argument {w.arg!r} {_WHY[w.kind()]}"
        return None

    def count_objects(self, tool: str, args: dict[str, Any]) -> int | None:
        """len of the count_arg value, 1 for anything else; None for a string this interpreter cannot decode."""
        rule = self.tools.get(tool)
        if rule and rule.count_arg:
            v = args.get(rule.count_arg)
            if isinstance(v, str):
                v = _json(v)  # count what the upstream SDK will see, not the raw string
            if v is _UNDECODABLE:
                return None
            return len(v) if isinstance(v, (list, tuple, set, dict)) else 1
        return 1


@dataclass(frozen=True)
class Decision:
    verdict: Literal["allow", "deny", "confirm"]
    rule_id: str
    tier: Tier | None = None
    dry_run: bool | None = None  # effective value forwarded upstream; None = argument untouched
    objects: int = 1
    message: str = ""
    preview: bool = True  # False: L2 tool without dry_run, prompt the human without a dry-run preview


class Engine:
    """Policy + the blast-radius window, which lives in the (shared) store."""

    def __init__(self, policy: Policy, store: Any = None):
        self.policy = policy
        self.store = store or MemoryStore()

    async def evaluate(self, tool: str, args: dict[str, Any], principal: str, confirmed: bool,
                       groups: tuple[str, ...] | list[str] = (), dry_run_supported: bool = True) -> Decision:
        p = self.policy
        tier = p.tier(tool, principal, groups)
        if tool not in p.tools:
            return Decision("deny", "allowlist.deny", message=f"tool {tool!r} is not allowlisted")
        if tier is None:
            return Decision("deny", "tier.unassigned", message=f"no tier for {tool!r} in environment {p.environment!r}")

        if (violation := p.args_violation(tool, args)) is not None:  # before tier, so nobody is asked to approve it
            return Decision("deny", "args.violation", tier, message=violation)

        n = p.count_objects(tool, args)
        blast = p.blast(tool)
        if n is None:  # unknown here, maybe a whole list upstream: refuse rather than count 1
            return Decision("deny", "blast_radius.per_call", tier, message=(
                f"argument {p.tools[tool].count_arg!r} cannot be decoded here (nesting depth or integer size beyond "
                "this proxy's limits), so its object count is unknown"))
        if n > blast.max_per_call:
            return Decision("deny", "blast_radius.per_call", tier, objects=n,
                            message=f"{n} objects > max_per_call={blast.max_per_call}")

        requested_dry = args.get("dry_run") is True
        unsupported = Decision("deny", "dry_run.unsupported", tier, objects=n,
                               message=f"{tool!r} declares no 'dry_run' argument; a forced dry-run cannot be made safe")
        if tier == "L0":
            d = Decision("allow", "tier.L0.read", tier, None, n)
        elif tier == "L1":
            if not dry_run_supported:
                return unsupported
            d = Decision("allow", "tier.L1.dry_run", tier, True, n, "L1: dry_run forced, never executes")
        elif tier == "L2":
            if requested_dry:
                if not dry_run_supported:
                    return unsupported
                d = Decision("allow", "tier.L2.dry_run", tier, True, n)
            elif confirmed:
                d = Decision("allow", "tier.L2.confirmed", tier, False if dry_run_supported else None, n)
            else:
                d = Decision("confirm", "tier.L2.confirm", tier, True if dry_run_supported else None, n,
                             "L2: human confirmation required", preview=dry_run_supported)
        else:
            # A client-supplied dry_run only counts as a dry run when the tool really has one; otherwise it is a
            # real execution that happens to carry a stray argument (and must be charged to the window).
            d = Decision("allow", "tier.L3.auto", tier, True if requested_dry and dry_run_supported else None, n)

        # Window check for anything that will (allow, real) or is about to (confirm: prompt the human) execute,
        # so nobody is asked to confirm an action the limit will refuse. Recording happens in `record`.
        if self._counts(d):
            used = await self.store.usage_sum(principal, tool, time.time() - blast.window_s)
            if used + n > blast.max_per_principal:
                return self._over(tier, n, used, blast)
        return d

    @staticmethod
    def _counts(d: Decision) -> bool:
        """Only writes that will (allow, real) or are about to (confirm) execute count against the window."""
        return d.tier != "L0" and (d.verdict == "confirm" or (d.verdict == "allow" and d.dry_run is not True))

    @staticmethod
    def _over(tier, n, used, blast) -> Decision:
        return Decision("deny", "blast_radius.per_principal", tier, objects=n,
                        message=f"{used}+{n} objects > max_per_principal={blast.max_per_principal} per {blast.window_s}s")

    async def reserve(self, principal: str, tool: str, d: Decision) -> Decision:
        """Atomically charge a real execution to the principal's window right before forwarding.
        Returns `d`, or a per_principal denial when a concurrent call took the last slot."""
        if not (d.verdict == "allow" and self._counts(d)):
            return d
        blast = self.policy.blast(tool)
        now = time.time()
        if await self.store.usage_reserve(principal, tool, d.objects, now, now - blast.window_s, blast.max_per_principal):
            return d
        return self._over(d.tier, d.objects, await self.store.usage_sum(principal, tool, now - blast.window_s), blast)

    async def refund(self, principal: str, tool: str, d: Decision) -> None:
        """Give back what `reserve` charged for `d`, when nothing reached the upstream. A negative usage row: the
        window sum nets it out, and it leaves the window together with the charge."""
        if d.verdict == "allow" and self._counts(d):
            await self.store.usage_add(principal, tool, -d.objects, time.time())
