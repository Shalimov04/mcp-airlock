"""Every GitHub workflow file parses and has the shape Actions expects.

A release.yml that is not valid YAML is flagged on every push and a tag push runs nothing.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
CHART_STEP = "chart appVersion must match the tag"


def _triggers(doc: dict) -> set[str]:
    # PyYAML reads the bare key `on` as the YAML 1.1 boolean True.
    on = doc["on"] if "on" in doc else doc.get(True)
    assert on is not None, "workflow has no `on` trigger"
    if isinstance(on, str):
        return {on}
    assert isinstance(on, (list, dict)), f"unexpected `on` value: {on!r}"
    return set(on)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_file_parses_and_has_the_shape_actions_expects(path: Path) -> None:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert doc.get("name")
    assert _triggers(doc)
    jobs = doc.get("jobs")
    assert isinstance(jobs, dict) and jobs
    for job_id, job in jobs.items():
        assert ("runs-on" in job) != ("uses" in job), job_id
        uses = job.get("uses")
        if isinstance(uses, str) and uses.startswith("./"):
            target = ROOT / uses[2:]
            assert target.is_file(), f"{job_id}: {uses} does not exist"
            called = yaml.safe_load(target.read_text(encoding="utf-8"))
            assert "workflow_call" in _triggers(called), f"{uses} lacks workflow_call"
        if "runs-on" in job:
            assert isinstance(job.get("steps"), list) and job["steps"], f"{job_id}: no steps"
        for i, step in enumerate(job.get("steps") or []):
            assert ("run" in step) != ("uses" in step), f"{job_id} step {i}"
            if "run" in step:
                assert isinstance(step["run"], str), f"{job_id} step {i}"


def _chart_step_text() -> str:
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8"))
    build = doc["jobs"].get("build")
    assert build, "release.yml has no `build` job"
    for step in build["steps"]:
        if step.get("name") == CHART_STEP:
            return step["run"]
    raise AssertionError(f"no step named {CHART_STEP!r}")


def _run_chart_step(ref: str) -> int:
    env = {**os.environ, "GITHUB_REF_NAME": ref}
    return subprocess.run(
        ["bash", "-e", "-c", _chart_step_text()], cwd=ROOT, env=env, capture_output=True
    ).returncode


def test_release_chart_check_passes_for_the_current_tree_and_fails_on_a_mismatch() -> None:
    # Read the line as text: an unquoted `appVersion: 0.3` would load as a float.
    chart = (ROOT / "charts" / "mcp-airlock" / "Chart.yaml").read_text("utf-8")
    line = next(ln for ln in chart.splitlines() if ln.startswith("appVersion:"))
    version = line.split(":", 1)[1].strip().strip("\"'")
    assert _run_chart_step("v" + version) == 0
    assert _run_chart_step("v9.9.9") == 1
