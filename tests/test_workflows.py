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


def _triggers(doc: dict) -> dict:
    # PyYAML reads the bare key `on` as the YAML 1.1 boolean True.
    return doc["on"] if "on" in doc else doc[True]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_file_parses_and_has_the_shape_actions_expects(path: Path) -> None:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert doc.get("name")
    assert "on" in doc or True in doc
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
        for i, step in enumerate(job.get("steps", [])):
            assert ("run" in step) != ("uses" in step), f"{job_id} step {i}"
            if "run" in step:
                assert isinstance(step["run"], str), f"{job_id} step {i}"


def _chart_step_text() -> str:
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8"))
    for step in doc["jobs"]["build"]["steps"]:
        if step.get("name") == CHART_STEP:
            return step["run"]
    raise AssertionError(f"no step named {CHART_STEP!r}")


def _run_chart_step(ref: str) -> int:
    env = {**os.environ, "GITHUB_REF_NAME": ref}
    return subprocess.run(
        ["bash", "-e", "-c", _chart_step_text()], cwd=ROOT, env=env, capture_output=True
    ).returncode


def test_release_chart_check_passes_for_the_current_tree_and_fails_on_a_mismatch() -> None:
    chart = yaml.safe_load((ROOT / "charts" / "mcp-airlock" / "Chart.yaml").read_text("utf-8"))
    assert _run_chart_step("v" + str(chart["appVersion"])) == 0
    assert _run_chart_step("v9.9.9") != 0
