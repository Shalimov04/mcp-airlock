"""The Helm chart renders what the values say. Needs `helm` on PATH, otherwise skipped."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "mcp-airlock"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def render(tmp_path: Path, values: str = "", *sets: str) -> list[dict]:
    cmd = ["helm", "template", "m", str(CHART), "--set", "upstream=http://u/mcp",
           "--set-file", f"policy={ROOT / 'policy.example.yaml'}"]
    if values:
        f = tmp_path / "values.yaml"
        f.write_text(values)
        cmd += ["-f", str(f)]
    for s in sets:
        # a plain `k=v` is a --set; an option such as --kube-version=1.29.0 is passed through
        cmd += [s] if s.startswith("--") else ["--set", s]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    return [d for d in yaml.safe_load_all(run.stdout) if d]


def refusal(tmp_path: Path, values: str = "", *sets: str) -> str:
    with pytest.raises(AssertionError) as e:
        render(tmp_path, values, *sets)
    return str(e.value)


def container(docs: list[dict]) -> dict:
    (dep,) = [d for d in docs if d["kind"] == "Deployment"]
    return dep["spec"]["template"]["spec"]["containers"][0]


def pod(docs: list[dict]) -> dict:
    (dep,) = [d for d in docs if d["kind"] == "Deployment"]
    return dep["spec"]["template"]["spec"]


def env(docs: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in container(docs)["env"]:
        assert e["name"] not in out, f"{e['name']} twice in env"
        out[e["name"]] = e
    return out


def test_whole_numbers_from_a_values_file_render_as_integers(tmp_path):
    # a values file decodes 104857600 as float64, and quote used to print 1.048576e+08
    docs = render(tmp_path, "env:\n  AIRLOCK_MAX_REQUEST_BYTES: 104857600\n  AIRLOCK_STORE_POOL_SIZE: 8\n"
                            "  RATIO: 1.5\nextraArgs: [--audit-max-bytes, 104857600, --audit-keep, 10]\n")
    c = container(docs)
    assert c["args"][-4:] == ["--audit-max-bytes", "104857600", "--audit-keep", "10"]
    e = env(docs)
    assert e["AIRLOCK_MAX_REQUEST_BYTES"]["value"] == "104857600"
    assert e["AIRLOCK_STORE_POOL_SIZE"]["value"] == "8"
    assert e["RATIO"]["value"] == "1.5"
    assert all(isinstance(a, str) for a in c["args"])


def test_set_values_still_render(tmp_path):
    docs = render(tmp_path, "", "env.AIRLOCK_STORE_POOL_SIZE=8", "env.AIRLOCK_TRUST_PRINCIPAL_HEADER=1")
    e = env(docs)
    assert e["AIRLOCK_STORE_POOL_SIZE"]["value"] == "8"
    assert e["AIRLOCK_TRUST_PRINCIPAL_HEADER"]["value"] == "1"


def test_a_map_in_env_is_refused_and_points_at_extra_env(tmp_path):
    msg = refusal(tmp_path, "env:\n  X: {valueFrom: {secretKeyRef: {name: a, key: b}}}\n")
    assert "extraEnv" in msg


def test_otlp_headers_are_a_credential(tmp_path):
    msg = refusal(tmp_path, "", "env.OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer x")
    assert "OTEL_EXPORTER_OTLP_HEADERS holds a credential" in msg
    msg = refusal(tmp_path, "extraEnv:\n  - name: OTEL_EXPORTER_OTLP_HEADERS\n    value: authorization=Bearer x\n")
    assert "OTEL_EXPORTER_OTLP_HEADERS holds a credential" in msg
    # read from existingSecret like the other optional credentials
    e = env(render(tmp_path, "", "existingSecret=s"))
    assert e["OTEL_EXPORTER_OTLP_HEADERS"]["valueFrom"]["secretKeyRef"] == {
        "name": "s", "key": "OTEL_EXPORTER_OTLP_HEADERS", "optional": True}


def test_extra_env_and_env_from_are_rendered_as_given(tmp_path):
    docs = render(tmp_path, "extraEnv:\n"
                            "  - name: OTEL_EXPORTER_OTLP_HEADERS\n"
                            "    valueFrom: {secretKeyRef: {name: otel, key: headers}}\n"
                            "  - name: TOKEN_COPY\n"
                            "    value: $(AIRLOCK_JWT_SECRET)\n"
                            "envFrom:\n  - secretRef: {name: more}\n")
    c = container(docs)
    e = env(docs)  # no duplicate: the extraEnv entry replaces the optional existingSecret one
    assert e["OTEL_EXPORTER_OTLP_HEADERS"]["valueFrom"]["secretKeyRef"] == {"name": "otel", "key": "headers"}
    names = [x["name"] for x in c["env"]]
    assert names.index("AIRLOCK_JWT_SECRET") < names.index("TOKEN_COPY")  # $(VAR) resolves to earlier entries
    assert c["envFrom"] == [{"secretRef": {"name": "more"}}]
    assert "envFrom" not in container(render(tmp_path))


def test_an_extra_env_name_that_is_also_set_elsewhere_is_refused(tmp_path):
    # Server-side apply rejects a container env with one name twice, client-side apply lets the
    # later entry win silently; both are worse than a chart message.
    msg = refusal(tmp_path, 'env: {FOO: "1"}\nextraEnv: [{name: FOO, value: "2"}]\n')
    assert "FOO is set in both env and extraEnv" in msg
    msg = refusal(tmp_path, "sharedStore: true\nexistingSecret: s\nextraEnv:\n"
                            "  - name: AIRLOCK_SECRET\n    valueFrom: {secretKeyRef: {name: a, key: b}}\n")
    assert "AIRLOCK_SECRET comes from existingSecret when sharedStore=true" in msg
    msg = refusal(tmp_path, 'extraEnv: [{name: A, value: "1"}, {name: A, value: "2"}]\n')
    assert "A is listed twice in extraEnv" in msg
    assert "needs a name" in refusal(tmp_path, 'extraEnv: [{value: "1"}]\n')
    # without sharedStore the key is not rendered by the chart, so an own source is fine
    e = env(render(tmp_path, "extraEnv:\n  - name: AIRLOCK_SECRET\n"
                             "    valueFrom: {secretKeyRef: {name: a, key: b}}\n"))
    assert e["AIRLOCK_SECRET"]["valueFrom"]["secretKeyRef"] == {"name": "a", "key": "b"}


def test_an_extra_env_value_must_be_a_string(tmp_path):
    # extraEnv is rendered as given, so an unquoted number reaches the API as a number, which
    # it rejects; env goes through the scalar helper and may stay unquoted
    assert "extraEnv value for NUM must be a string" in refusal(tmp_path, "extraEnv: [{name: NUM, value: 5}]\n")
    assert env(render(tmp_path, 'extraEnv: [{name: NUM, value: "5"}]\n'))["NUM"]["value"] == "5"


def test_pre_stop_sleep_and_grace_period(tmp_path):
    docs = render(tmp_path)
    assert container(docs)["lifecycle"] == {"preStop": {"sleep": {"seconds": 5}}}
    assert pod(docs)["terminationGracePeriodSeconds"] == 30
    docs = render(tmp_path, "preStopSeconds: 0\nterminationGracePeriodSeconds: 45\n")
    assert "lifecycle" not in container(docs)
    assert pod(docs)["terminationGracePeriodSeconds"] == 45
    assert "terminationGracePeriodSeconds must exceed preStopSeconds" in refusal(
        tmp_path, "preStopSeconds: 10\nterminationGracePeriodSeconds: 10\n")
    # a negative sleep passed the grace-period check and was left for the API server to reject
    assert "preStopSeconds must be 0 or more" in refusal(tmp_path, "preStopSeconds: -1\n")


def test_pre_stop_sleep_is_refused_on_a_cluster_older_than_1_30(tmp_path):
    # such an API server drops the sleep field and then rejects a preStop with no handler
    msg = refusal(tmp_path, "", "--kube-version=1.29.5")
    assert "needs Kubernetes 1.30+" in msg and "set preStopSeconds=0" in msg
    assert "lifecycle" not in container(render(tmp_path, "preStopSeconds: 0\n", "--kube-version=1.29.5"))
    assert "lifecycle" in container(render(tmp_path, "", "--kube-version=1.30.0"))
