"""Tests du sink via AttrLhs dans `_transfer_assign` (symétrie SubscriptLhs).

Le commit `b7c4de8` avait ajouté la détection de sinks sur `SubscriptLhs`
(`obj[key] = source`). Ce module valide l'extension à `AttrLhs`
(`obj.attr = source`), qui matche le **chemin canonique complet**
(`user.is_admin`) contre les sink patterns.

Règle support : `taint_sensitive_attr_write` (écriture d'une donnée
user-contrôlée vers un attribut privilégié — escalade de privilèges,
CWE-915 / CWE-639).

Référence moteur : `sca/dataflow/transfer.py::_lhs_sink_target`.
"""
from __future__ import annotations

from pathlib import Path

from sca.executors.dataflow_taint import run_taint_rule


def _load_rule(rule_id: str):
    """Charge une règle taint depuis son .sca (sources/sinks/sanitizers réels)."""
    rule_path = (
        Path(__file__).parent.parent.parent
        / "sca" / "rules" / "builtin" / "python" / "security" / f"{rule_id}.sca"
    )
    rule = {
        "id": rule_id,
        "mode": "taint",
        "severity": "HIGH",
        "sources": [],
        "sinks": [],
        "sanitizers": [],
    }
    for line in rule_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("source "):
            parts = line.split(None, 1)[1].split()
            pattern = parts[0]
            kind = "http"
            for p in parts[1:]:
                if p.startswith("kind="):
                    kind = p[5:]
            rule["sources"].append({"pattern": pattern, "kind": kind})
        elif line.startswith("sink "):
            rule["sinks"].append({"pattern": line.split(None, 1)[1].strip()})
        elif line.startswith("sanitizer "):
            rule["sanitizers"].append({"pattern": line.split(None, 1)[1].strip()})
    return rule


_RULE = _load_rule("taint_sensitive_attr_write")


class TestAttrLhsSinkDetection:
    """Le sink AttrLhs doit flaguer une écriture taintée vers un attribut sensible."""

    def test_direct_assign_to_is_admin_flags(self):
        src = """
from flask import request
def update(user):
    user.is_admin = request.form.get('is_admin')
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"user.is_admin = request.form.get(...) doit flaguer (got {len(findings)})"
        )

    def test_assign_via_intermediate_var_flags(self):
        # La source transite par une variable intermédiaire avant l'écriture.
        src = """
from flask import request
def update(user):
    value = request.form.get('role')
    user.role = value
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"propagation via variable puis user.role = value doit flaguer "
            f"(got {len(findings)})"
        )

    def test_nested_attribute_path_flags(self):
        # Chemin imbriqué : current_user.account.permissions.
        src = """
from flask import request
def update(current_user):
    current_user.account.permissions = request.json
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"chemin imbriqué se terminant par .permissions doit flaguer "
            f"(got {len(findings)})"
        )


class TestAttrLhsSinkNoFalsePositive:
    """Pas de détection en l'absence d'attribut sensible ou de taint."""

    def test_non_sensitive_attribute_no_finding(self):
        # `user.name` n'est pas un attribut porteur d'autorisation → pas de sink.
        src = """
from flask import request
def update(user):
    user.name = request.form.get('name')
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"user.name (attribut non sensible) ne doit pas flaguer "
            f"(got {len(findings)})"
        )

    def test_constant_value_no_finding(self):
        # Valeur constante (non taintée) → pas de sink, même attribut sensible.
        src = """
def update(user):
    user.is_admin = False
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"user.is_admin = False (valeur constante) ne doit pas flaguer "
            f"(got {len(findings)})"
        )

    def test_validated_value_no_finding(self):
        # La valeur est validée par un guard (`if not re.fullmatch(...): abort`)
        # avant l'écriture → taint nettoyé (Phase 7 guard sanitizer).
        src = """
from flask import request
def update(user):
    role = request.form.get('role')
    if not re.fullmatch(r'viewer|editor', role):
        abort(400)
    user.role = role
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"valeur validée par guard re.fullmatch ne doit pas flaguer "
            f"(got {len(findings)})"
        )
