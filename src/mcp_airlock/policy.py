"""Flat-YAML policy: default-deny allowlist, per-(tool, environment) risk tier,
output cap, blast radius, flat `where` conditions on argument values. No DSL."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .store import USAGE_RETENTION_S, MemoryStore


def _load_sre() -> tuple[Any, Any]:
    """The stdlib's own regex parse tree; `re` has no public one. 3.11+ has it as re._parser/re._constants and keeps
    sre_parse/sre_constants as deprecated aliases, so either name may disappear first."""
    import importlib
    for parser, constants in (("re._parser", "re._constants"), ("sre_parse", "sre_constants")):
        try:
            return importlib.import_module(constants), importlib.import_module(parser)
        except ImportError:
            continue
    # without the parse tree the cost check cannot run, and a policy it never looked at must not load
    raise RuntimeError("this Python has no regex parser module (re._parser, sre_parse): the where-regex cost check "
                       "cannot run, so mcp-airlock refuses to start; use a Python version it supports")


_sre, _sre_parser = _load_sre()

# A where regex runs on the event loop with the GIL held, so its cost bounds how long one request can stall the
# whole proxy. Patterns that can go exponential are refused at load (regex_risk), and so are those whose polynomial
# degree the value cap below does not bound (regex_unbounded_repeats); for the rest the value length is capped,
# and a longer value fails the rule.
REGEX_MAX_CHARS = 1024
REGEX_MAX_UNBOUNDED = 2  # unbounded repeats in a row a pattern may have: two is milliseconds at the cap, three seconds, four tens of seconds

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
            if (why := regex_risk(self.regex)) is not None:
                raise ValueError(f"regex {self.regex!r} has {why}: it can take exponential time on a crafted value and "
                                 "freeze the proxy; use a single character class, or make each iteration start or end "
                                 "with a character the group cannot match elsewhere")
            if (n := regex_unbounded_repeats(self.regex)) > REGEX_MAX_UNBOUNDED:
                raise ValueError(f"regex {self.regex!r} has {n} unbounded repeats in a row: on a {REGEX_MAX_CHARS}-character "
                                 f"value it can run for seconds and freeze the proxy; use at most {REGEX_MAX_UNBOUNDED}, "
                                 "or separate them with a character the repeats cannot match")
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
            return isinstance(v, str) and len(v) <= REGEX_MAX_CHARS and re.fullmatch(self.regex, v) is not None
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


def _over_regex_cap(v: Any) -> bool:
    return any(isinstance(x, str) and len(x) > REGEX_MAX_CHARS for x in (v if isinstance(v, (list, tuple)) else [v]))


_WHY = {"equals": "does not equal the required value", "in": "is not in the allowed values",
        "not_in": "is in the forbidden values", "regex": "does not match the required pattern"}


# ---------------------------------------------------------------- regex cost
# Backtracking goes exponential when the engine can split the same characters between iterations of a repetition
# in many ways: a repetition inside a repetition ((a+)+), an alternation inside a repetition whose alternatives can
# start alike ((a|aa)+) or a backreference. A fixed outer count does not help: (.*a){12} has about 1024^12 splits
# to try on a 1024-character value. These are refused when the policy loads. A nested repetition is harmless when
# the group has a fixed width (((ab){2})+) or when every iteration starts or ends with a character the rest of the
# group never consumes ((\.[a-z]{1,63})*, (\d{1,3}\.){3}): the iteration boundaries are then fixed and nothing can
# shift between them. Everything else is polynomial in the value length, of a degree given by the unbounded repeats
# that run one after another and can take each other's characters. Measured with the stdlib re on '-' * n + '!':
# two repeats take milliseconds at 1024 characters (.*-.*-prod: about 3 ms, 50 ms at 4096), three take one to a few
# seconds (.*-.*-.*-prod: about a second, a minute at 4096) and four tens of seconds. The cap alone is enough for two;
# three or more are refused, since one such call stalls every other request for seconds.

_REPEATS = (_sre.MAX_REPEAT, _sre.MIN_REPEAT, _sre.POSSESSIVE_REPEAT)
_ATOMS = (_sre.LITERAL, _sre.NOT_LITERAL, _sre.IN, _sre.ANY)
_CATEGORY = {_sre.CATEGORY_DIGIT: r"\d", _sre.CATEGORY_NOT_DIGIT: r"\D", _sre.CATEGORY_SPACE: r"\s",
             _sre.CATEGORY_NOT_SPACE: r"\S", _sre.CATEGORY_WORD: r"\w", _sre.CATEGORY_NOT_WORD: r"\W"}


def regex_risk(pattern: str) -> str | None:
    """What lets `pattern` take exponential time on a crafted value, or None when nothing does."""
    return _risk(_sre_parser.parse(pattern), nested=False)


def regex_unbounded_repeats(pattern: str) -> int:
    """How many unbounded repeats (`*`, `+`, `{n,}`) the pattern runs one after another that can take each other's
    characters: two can take quadratic time in the value length, three cubic, and so on. A repeat that must be
    followed by a character its body cannot match ([^/]+/) has one place to stop and is not counted, nor is a
    repeat inside another one."""
    return _unbounded(_sre_parser.parse(pattern), top=True)


def _risk(seq: Any, nested: bool) -> str | None:
    """`nested`: this sequence is inside a repetition whose iterations can share characters."""
    for op, av in seq:
        found = None
        if op in (_sre.GROUPREF, _sre.GROUPREF_EXISTS):
            found = "a backreference"
        elif op in _REPEATS:
            mn, mx, body = av
            # `?` never iterates; any repeat that can run twice has splits to try, a fixed count ((.*a){12}) as
            # much as an unbounded one. A group of fixed width splits one way, unless two alternatives in it can
            # match the same characters.
            repeats = mx > 1
            if nested and mx > mn:  # an optional item inside a loop splits too: (a?a)+ is (a|aa)+
                found = "a repetition inside a repetition"
            elif repeats and any(op2 is _sre.BRANCH and _overlapping(av2[1]) for op2, av2 in _walk(body)):
                found = "an alternation inside a repetition"
            else:
                found = _risk(body, nested or (repeats and _width(body) is None and not _separated(body)))
        elif op is _sre.SUBPATTERN:
            found = _risk(av[3], nested)
        elif op is _sre.BRANCH:
            found = next((r for alt in av[1] if (r := _risk(alt, nested)) is not None), None)
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            found = _risk(av[1], nested)
        elif op is _sre.ATOMIC_GROUP:
            found = _risk(av, nested)
        if found is not None:
            return found
    return None


def _walk(seq: Any, lookarounds: bool = True):
    """Every node of the tree, depth first. Lookaround bodies consume nothing and can be left out."""
    for op, av in seq:
        yield op, av
        if op in _REPEATS:
            yield from _walk(av[2], lookarounds)
        elif op is _sre.SUBPATTERN:
            yield from _walk(av[3], lookarounds)
        elif op is _sre.BRANCH:
            for alt in av[1]:
                yield from _walk(alt, lookarounds)
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            if lookarounds:
                yield from _walk(av[1], lookarounds)
        elif op is _sre.ATOMIC_GROUP:
            yield from _walk(av, lookarounds)
        elif op is _sre.GROUPREF_EXISTS:
            for alt in av[1:]:
                if alt is not None:
                    yield from _walk(alt, lookarounds)


def _width(seq: Any) -> int | None:
    """How many characters the sequence always matches, None when that varies."""
    total = 0
    for op, av in seq:
        w: int | None
        if op in _ATOMS:
            w = 1
        elif op is _sre.AT or op in (_sre.ASSERT, _sre.ASSERT_NOT):
            w = 0  # anchors and lookarounds consume nothing
        elif op in _REPEATS:
            mn, mx, body = av
            bw = _width(body)
            w = mn * bw if mn == mx and bw is not None else None
        elif op is _sre.SUBPATTERN:
            w = _width(av[3])
        elif op is _sre.ATOMIC_GROUP:
            w = _width(av)
        elif op is _sre.BRANCH:
            widths = {_width(alt) for alt in av[1]}
            w = widths.pop() if len(widths) == 1 else None
        else:
            w = None  # a backreference, or an opcode this check does not model
        if w is None:
            return None
        total += w
    return total


def _separated(body: Any) -> bool:
    """Every iteration of the repeated group starts, or ends, with a character that the rest of the group never
    consumes: the iteration boundaries are then fixed."""
    for edge, rest in (_head(body), _tail(body)):
        chars = _chars(edge)
        if chars is not None and not any(_consumes(rest, c) for c in chars):
            return True
    return False


def _overlapping(alts: list) -> bool:
    """Can two alternatives start with the same character, or one of them with nothing?"""
    sets = [_chars(_head(alt)[0]) for alt in alts]
    if any(s is None for s in sets):
        return True
    folded = [{o for c in s for o in _fold(c)} for s in sets]
    return any(a & b for i, a in enumerate(folded) for b in folded[i + 1:])


def _head(seq: Any) -> tuple[Any, list]:
    """The first item of the sequence, looking through leading groups, and everything after it."""
    items = list(seq)
    while items and items[0][0] is _sre.SUBPATTERN:
        items = list(items[0][1][3]) + items[1:]
    return (items[0], items[1:]) if items else (None, [])


def _tail(seq: Any) -> tuple[Any, list]:
    """The last item of the sequence, looking through trailing groups, and everything before it."""
    items = list(seq)
    while items and items[-1][0] is _sre.SUBPATTERN:
        items = items[:-1] + list(items[-1][1][3])
    return (items[-1], items[:-1]) if items else (None, [])


def _chars(item: Any) -> set[int] | None:
    """The characters a literal or a small plain class matches; None for anything wider or for no item."""
    if item is None:
        return None
    op, av = item
    if op is _sre.LITERAL:
        return {av}
    if op is _sre.IN and all(k in (_sre.LITERAL, _sre.RANGE) for k, _ in av):
        chars = {c for k, v in av for c in ([v] if k is _sre.LITERAL else range(v[0], v[1] + 1))}
        return chars if len(chars) <= 64 else None
    return None  # a class with a category or a negation, a dot, an anchor or a nested repeat


def _fold(c: int) -> set[int]:
    return {c} | {ord(x) for x in (chr(c).lower(), chr(c).upper()) if len(x) == 1}  # (?i) may be on


def _consumes(seq: Any, c: int) -> bool:
    """Can some character-consuming item in the sequence match the character `c` (in any case)?"""
    for op, av in _walk(seq, lookarounds=False):
        if op in (_sre.GROUPREF, _sre.GROUPREF_EXISTS):
            return True  # whatever the group matched: unknown, so assume yes
        if op in _ATOMS and any(_atom_matches(op, av, o) for o in _fold(c)):
            return True
    return False


def _atom_matches(op: Any, av: Any, c: int) -> bool:
    if op is _sre.LITERAL:
        return av == c
    if op is _sre.NOT_LITERAL:
        return av != c
    if op is _sre.ANY:
        return True  # a dot takes everything but a newline, which no separator should rely on
    negate = bool(av) and av[0][0] is _sre.NEGATE
    hit = False
    for k, v in av[1:] if negate else av:
        if k is _sre.LITERAL:
            hit |= v == c
        elif k is _sre.RANGE:
            hit |= v[0] <= c <= v[1]
        elif k is _sre.CATEGORY and v in _CATEGORY:
            hit |= re.fullmatch(_CATEGORY[v], chr(c)) is not None
        else:
            return True  # a category this check does not model: assume it matches
    return hit != negate


def _unbounded(seq: Any, top: bool = False) -> int:
    """`top`: the sequence is the whole pattern, so its end is the end of the value (a full match)."""
    items = list(seq)
    n = 0
    for i, (op, av) in enumerate(items):
        if op in _REPEATS:
            if av[1] != _sre.MAXREPEAT:
                n += _unbounded(av[2])
            elif not _stops_at(av[2], items[i + 1:], end=top and all(op2 is _sre.AT for op2, _ in items[i + 1:])):
                n += 1
        elif op is _sre.SUBPATTERN:
            n += _unbounded(av[3])
        elif op is _sre.BRANCH:
            n += max(_unbounded(alt) for alt in av[1])
        elif op in (_sre.ASSERT, _sre.ASSERT_NOT):
            n += _unbounded(av[1])
        elif op is _sre.ATOMIC_GROUP:
            n += _unbounded(av)
    return n


def _stops_at(body: Any, after: Any, end: bool) -> bool:
    """Has the repeat one place to stop: the end of the value (`end`), or a character its body can never match
    at the start of what follows (`after`)?"""
    if end:
        return True
    nxt = _head(after)[0]
    while nxt is not None and nxt[0] in _REPEATS and nxt[1][0] >= 1:  # a mandatory repeat starts with its body's head
        nxt = _head(nxt[1][2])[0]
    chars = _chars(nxt)
    return chars is not None and not any(_consumes(body, c) for c in chars)


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
        if environment and isinstance(data, dict):  # a list or scalar document fails validation below, not here
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
            if w.regex is not None and _over_regex_cap(args[w.arg]):  # the pattern is never tried on it: fails closed
                return f"argument {w.arg!r} is longer than {REGEX_MAX_CHARS} characters, more than a pattern is tried on"
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
    reserved_ts: float | None = None  # when `reserve` charged the window for this decision; None: not charged


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
            return replace(d, reserved_ts=now)
        return self._over(d.tier, d.objects, await self.store.usage_sum(principal, tool, now - blast.window_s), blast)

    async def refund(self, principal: str, tool: str, d: Decision) -> None:
        """Give back what `reserve` charged for `d`, when nothing reached the upstream. A negative usage row at the
        charge's own timestamp: the window sum nets the two out, and they leave the window together (a row stamped
        now would understate the sum for as long as the connect attempt took once the charge has left)."""
        if d.reserved_ts is not None:
            await self.store.usage_add(principal, tool, -d.objects, d.reserved_ts)
