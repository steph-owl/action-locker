"""Regression tests for previously known parser-backend refinement gaps.

These tests express the one-way relationship between the experimental lab
parser and the authoritative stable parser::

    lab accepts(document) -> stable accepts(document)

and, when both accept, both backends must emit the same normalized references.

Each case started life as a strict xfail describing an open gap. All of them
have since been fixed and promoted (per this module's own original
instructions) to ordinary always-on regression tests: lab/0 now fails closed
on implicitly typed plain scalars in `uses` slots and on tracked mapping
keys, duplicate keys in any tracked block mapping, and unfinished quoted or
flow syntax at end of file; stable availability requires the exact ruamel
pin, not mere importability.
"""

import pytest

import action_locker
from action_locker import LegacyRegexBackend, StructuralYamlBackend


def parse_pair(tmp_path, content):
    """Parse identical workflow bytes with stable and lab/0."""
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow = workflow_dir / "ci.yml"
    workflow.write_text(content)
    return (
        StructuralYamlBackend().parse_file(tmp_path, workflow),
        LegacyRegexBackend().parse_file(tmp_path, workflow),
    )


def normalized_references(result):
    """Reference identity used by compare mode; source positions are noise."""
    return tuple(
        (
            ref.semantic_path,
            ref.kind,
            ref.raw_target,
            ref.action,
            ref.ref,
        )
        for ref in result.references
    )


def assert_lab_refines_stable(stable, lab):
    """Assert the asymmetric safety contract the lab parser is targeting."""
    assert not lab.accepted or stable.accepted, (
        "lab/0 accepted bytes that stable rejected; "
        f"stable diagnostics={[d.code for d in stable.diagnostics]!r}, "
        f"lab diagnostics={[d.code for d in lab.diagnostics]!r}"
    )
    if lab.accepted:
        assert normalized_references(lab) == normalized_references(stable)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("null", id="null"),
        pytest.param("true", id="boolean"),
        pytest.param("123", id="integer"),
        pytest.param("2026-07-12", id="timestamp-like"),
    ],
)
def test_plain_uses_scalars_respect_yaml_types(tmp_path, value):
    stable, lab = parse_pair(
        tmp_path,
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        f"      - uses: {value}\n",
    )

    assert_lab_refines_stable(stable, lab)


def test_plain_job_id_respects_yaml_types(tmp_path):
    stable, lab = parse_pair(
        tmp_path,
        "jobs:\n"
        "  true:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
    )

    assert_lab_refines_stable(stable, lab)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: echo first\n"
            "    steps:\n"
            "      - uses: attacker/action@main\n",
            id="duplicate-steps",
        ),
        pytest.param(
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    runs-on: windows-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n",
            id="duplicate-job-field",
        ),
        pytest.param(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        env:\n"
            "          FLAG: one\n"
            "          FLAG: two\n",
            id="duplicate-nested-field",
        ),
    ],
)
def test_duplicate_mapping_keys_fail_closed(tmp_path, content):
    stable, lab = parse_pair(tmp_path, content)

    assert_lab_refines_stable(stable, lab)


@pytest.mark.parametrize(
    "trailing_content",
    [
        pytest.param("broken: [unclosed\n", id="unclosed-flow-collection"),
        pytest.param('broken: "unterminated\n', id="unterminated-quote"),
    ],
)
def test_invalid_trailing_yaml_fails_closed(tmp_path, trailing_content):
    stable, lab = parse_pair(
        tmp_path,
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "\n"
        + trailing_content,
    )

    assert_lab_refines_stable(stable, lab)


def test_stable_backend_availability_requires_exact_ruamel_pin(monkeypatch):
    monkeypatch.setattr(action_locker, "STABLE_RUAMEL_PIN", "0.0.0-test")

    assert not action_locker.stable_backend_available()
