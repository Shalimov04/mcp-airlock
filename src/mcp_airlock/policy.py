"""Flat-YAML policy: default-deny allowlist, per-(tool, environment) risk tier,
output cap, blast radius. No DSL; if you need conditions, write a second YAML."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .store import USAGE_RETENTION_S, MemoryStore

Tier = Literal["L0", "L1", "L2", "L3"]
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


class ToolRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tiers: dict[str, Tier]  # environment -> tier; no entry for the running env = deny
    principals: dict[str, dict[str, Tier]] = Field(default_factory=dict)  # "alice" or "group:oncall" -> env -> tier
    description: str = ""
    count_arg: str | None = None  # list-valued argument whose length is the object count
    output: OutputCap | None = None
    blast_radius: BlastRadius | None = None


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
        for key in ([principal] if principal else []) + [f"group:{g}" for g in groups]:  # principal beats group, first group wins
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

    def count_objects(self, tool: str, args: dict[str, Any]) -> int:
        rule = self.tools.get(tool)
        if rule and rule.count_arg:
            v = args.get(rule.count_arg)
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

        n = p.count_objects(tool, args)
        blast = p.blast(tool)
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
