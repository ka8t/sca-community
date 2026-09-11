"""
Mixin comparaison — baseline, historique, export JSON et rétention.
"""
import os
import re
import json
import logging
from datetime import datetime, timedelta
from dataclasses import asdict, fields
from typing import List, Dict, Optional

from sca.models import Finding, ComparisonResult

logger = logging.getLogger("sca.comparison")


class AuditComparisonMixin:
    """Baseline comparison and JSON/SARIF/SBOM export methods."""

    def _finding_key(self, f: Finding) -> str:
        """Generate a base key identifying a finding (file + rule + code
        fingerprint). Excludes the line number so it survives a line shift
        caused by an unrelated change elsewhere in the file."""
        code_hash = self._code_hash(f.code)
        return f"{f.file}:{f.rule}:{code_hash}"

    def _index_findings(self, findings: List[Finding]) -> Dict[str, Finding]:
        """Index a list of findings by a unique key.

        Multiple findings can share the same base key (same file, same
        rule, same code fingerprint) when an identical vulnerable pattern
        appears several times in a file. A dict indexed only by the base
        key would silently overwrite entries, skewing the new/resolved/
        unchanged counters. Disambiguates with an index suffix assigned in
        line order within each group sharing the same base key.
        """
        grouped: Dict[str, List[Finding]] = {}
        for f in findings:
            grouped.setdefault(self._finding_key(f), []).append(f)
        indexed: Dict[str, Finding] = {}
        for base_key, group in grouped.items():
            for i, f in enumerate(sorted(group, key=lambda x: x.line)):
                indexed[f"{base_key}:{i}"] = f
        return indexed

    @staticmethod
    def _code_hash(code: str) -> int:
        """Compute a deterministic code hash (CRC32, stable across sessions and machines)."""
        import zlib
        if not code:
            return 0
        return zlib.crc32(code[:50].encode("utf-8")) & 0xFFFFFFFF

    def _find_latest_baseline(self) -> Optional[str]:
        """Find the most recent JSON file in audit-datas/."""
        json_files = self._list_data_files()
        if not json_files:
            logger.info(self.t_console("log_no_baseline").format(path=self._rel(self.datas_dir)))
            return None

        # Sort by name (contains the timestamp) and take the most recent
        json_files.sort(reverse=True)
        baseline = os.path.join(self.datas_dir, json_files[0])
        logger.info(self.t_console("log_baseline_found").format(file=json_files[0], count=len(json_files)))
        return baseline

    def _load_history(self) -> List[Dict]:
        """Load the full audit history for the trend chart."""
        json_files = self._list_data_files()
        if not json_files:
            return []

        # Sort by date (oldest to most recent)
        json_files.sort()

        # Limit for the chart (config or default 10)
        max_history = self.config.get("reports", {}).get("max_history", 10)
        json_files = json_files[-max_history:]

        history = []
        for filename in json_files:
            filepath = os.path.join(self.datas_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    tests_data = data.get("tests", {})
                    db_data = data.get("database") or {}
                    db_stats = db_data.get("stats") or {}
                    db_changes = db_stats.get("changes", {})
                    history.append({
                        "timestamp": data.get("timestamp", "N/A"),
                        "date": data.get("date", ""),
                        "totals": data.get("totals", {}),
                        "tests": {
                            "passed": tests_data.get("passed", 0) if tests_data else 0,
                            "failed": tests_data.get("failed", 0) if tests_data else 0,
                            "total": tests_data.get("total", 0) if tests_data else 0,
                            "success_rate": tests_data.get("success_rate", 0) if tests_data else 0,
                        },
                        "database": {
                            "tables": db_stats.get("tables_count", 0),
                            "columns": db_stats.get("columns_count", 0),
                            "indexes": db_stats.get("indexes_count", 0),
                            "changes": sum([
                                db_changes.get("added", {}).get("tables", 0),
                                db_changes.get("added", {}).get("columns", 0),
                                db_changes.get("added", {}).get("indexes", 0),
                                db_changes.get("dropped", {}).get("tables", 0),
                                db_changes.get("dropped", {}).get("columns", 0),
                                db_changes.get("dropped", {}).get("indexes", 0),
                                db_changes.get("modified", {}).get("columns", 0),
                            ])
                        },
                        "timings": data.get("timings", {})
                    })
            except Exception:
                continue

        return history

    def _export_json(self):
        """Export the audit results to JSON to serve as a future baseline."""
        # Collect all findings + enrich with metadata.cwe/owasp/iso27001
        # from the source rule (useful information for tools consuming the JSON
        # — not stored on Finding since it's redundant with the rule).
        rules_idx = getattr(self, "_cached_json_rules", {}) or {}
        all_findings = []
        for cat in self.categories.values():
            for f in cat.findings:
                d = asdict(f)
                rk = f.rule_key or f.rule
                meta = rules_idx.get(rk, {}).get("metadata") or {}
                if meta:
                    d["compliance"] = {
                        "cwe": meta.get("cwe") or [],
                        "owasp": meta.get("owasp") or "",
                        "iso27001": meta.get("iso27001") or [],
                        "asvs": meta.get("asvs") or [],
                    }
                all_findings.append(d)

        # Statistics (including all severity levels)
        totals = {
            "CRITICAL": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in all_findings if f["severity"] == "LOW"),
            "INFO": sum(1 for f in all_findings if f["severity"] == "INFO"),
        }

        # DATABASE-specific data (full schema + stats + findings)
        database_findings = [f for f in all_findings if f.get("category") == "DATABASE"]
        database_data = None
        if self.database_schema or database_findings:
            database_data = {
                "total_changes": len(database_findings),
                "by_severity": {
                    "CRITICAL": sum(1 for f in database_findings if f["severity"] == "CRITICAL"),
                    "HIGH": sum(1 for f in database_findings if f["severity"] == "HIGH"),
                    "MEDIUM": sum(1 for f in database_findings if f["severity"] == "MEDIUM"),
                    "LOW": sum(1 for f in database_findings if f["severity"] == "LOW"),
                    "INFO": sum(1 for f in database_findings if f["severity"] == "INFO"),
                },
                "changes": database_findings,
                "schema": self.database_schema,  # Full schema to serve as a baseline
                "stats": self.database_stats     # Schema statistics
            }

        # Test results
        test_data = None
        if self.test_results:
            test_data = {
                "passed": self.test_results.passed,
                "failed": self.test_results.failed,
                "errors": self.test_results.errors,
                "skipped": self.test_results.skipped,
                "total": self.test_results.total,
                "duration": self.test_results.duration,
                "success_rate": self.test_results.success_rate,
                "failed_tests": self.test_results.failed_tests,
                "error_tests": self.test_results.error_tests,
            }

        # Compliance ISO 27001
        compliance_data = None
        compliance_enabled = self.config.get("compliance", {}).get("iso27001", {}).get("enabled", True)
        if compliance_enabled and self.iso27001_mapping:
            compliance_data = {
                "iso27001": self._compute_iso27001_compliance()
            }
            # Strip control details to keep the JSON light (keep only the summary)
            if "controls" in compliance_data["iso27001"]:
                del compliance_data["iso27001"]["controls"]

        # Compliance ASVS
        asvs_enabled = self.config.get("compliance", {}).get("asvs", {}).get("enabled", True)
        if asvs_enabled and self.asvs_mapping:
            if compliance_data is None:
                compliance_data = {}
            compliance_data["asvs"] = self._compute_asvs_compliance()
            if "requirements" in compliance_data["asvs"]:
                del compliance_data["asvs"]["requirements"]

        # Compliance NIST CSF 2.0
        nist_enabled = self.config.get("compliance", {}).get("nist_csf", {}).get("enabled", True)
        if nist_enabled and self.nist_csf_mapping:
            if compliance_data is None:
                compliance_data = {}
            compliance_data["nist"] = self._compute_nist_csf_compliance()
            # Strip subcategory details to keep the JSON light (keep only the summary)
            if "subcategories" in compliance_data["nist"]:
                del compliance_data["nist"]["subcategories"]

        export_data = {
            "version": "3.5",
            "metadata": {
                "tool_name": self.tool_name,
                "company_name": self.company_name,
                "prefix": self.brand_prefix,
            },
            "timestamp": self.timestamp,
            "date": self.now.isoformat(),
            "quick_mode": self.quick_mode,
            "languages": sorted(self._languages),
            "totals": totals,
            "tests": test_data,
            "timings": self.audit_timings if self.audit_timings else None,
            "dependencies": self.dependency_stats if self.dependency_stats else None,
            "cicd": self.cicd_stats if self.cicd_stats else None,
            "database": database_data,
            "compliance": compliance_data,
            "findings": all_findings,
        }

        with open(self.data_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

    def _export_sarif(self):
        """Export the audit results in SARIF 2.1.0 format (GitHub/GitLab compatible)."""
        # Collect the rules in use
        rules_map = {}  # rule_key → index
        rules_list = []
        for cat in self.categories.values():
            for f in cat.findings:
                rk = f.rule_key or f.rule
                if rk not in rules_map:
                    rules_map[rk] = len(rules_list)
                    rule_data = self._rule(rk) if f.rule_key else {}
                    # SARIF properties.tags: de facto standard for exposing
                    # CWE/OWASP to consuming tools (DefectDojo,
                    # GitHub code-scanning, etc.).
                    meta = (rule_data or {}).get("metadata") or {}
                    tags = [f.category.lower()]
                    cwes = meta.get("cwe") or []
                    if isinstance(cwes, str):
                        cwes = [cwes]
                    tags.extend(cwes)
                    if meta.get("owasp"):
                        tags.append(meta["owasp"])
                    rules_list.append({
                        "id": rk,
                        "name": f.rule,
                        "shortDescription": {"text": f.rule},
                        "fullDescription": {"text": rule_data.get("risk", f.risk) if rule_data else f.risk},
                        "defaultConfiguration": {
                            "level": self._severity_to_sarif_level(f.severity)
                        },
                        "properties": {"category": f.category, "tags": tags},
                    })

        # Collect the results
        results = []
        for cat in self.categories.values():
            for f in cat.findings:
                rk = f.rule_key or f.rule
                result = {
                    "ruleId": rk,
                    "ruleIndex": rules_map.get(rk, 0),
                    "level": self._severity_to_sarif_level(f.severity),
                    "message": {"text": f.risk or f.rule},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }],
                }
                if f.solution:
                    result["fixes"] = [{"description": {"text": f.solution}}]
                # codeFlows for findings with taint_flow (SARIF 2.1.0 standard)
                if getattr(f, "taint_flow", None):
                    tf = f.taint_flow
                    locations = []
                    # Source
                    locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": tf.source_file.replace(os.sep, "/")},
                                "region": {"startLine": max(1, tf.source_line)},
                            },
                            "message": {"text": f"Source: {tf.source_expr}"},
                        },
                    })
                    # Propagation chain
                    for step_line, step_var, step_code in tf.chain:
                        locations.append({
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": tf.source_file.replace(os.sep, "/")},
                                    "region": {"startLine": max(1, step_line)},
                                },
                                "message": {"text": f"{step_var}: {step_code[:80]}"},
                            },
                        })
                    # Sink
                    locations.append({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": tf.sink_file.replace(os.sep, "/")},
                                "region": {"startLine": max(1, tf.sink_line)},
                            },
                            "message": {"text": f"Impact: {tf.sink_expr}"},
                        },
                    })
                    result["codeFlows"] = [{"threadFlows": [{"locations": locations}]}]
                results.append(result)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.config.get("project", {}).get("version", "1.0"),
                        "informationUri": self.config.get("brand", {}).get("website_url") or "https://codefixture.com",
                        "rules": rules_list,
                    }
                },
                "results": results,
            }],
        }

        sarif_path = os.path.join(self.reports_dir, f"{self.brand_prefix}-SARIF-{self.timestamp}.sarif")
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        self._sarif_path = sarif_path

    @staticmethod
    def _severity_to_sarif_level(severity: str) -> str:
        """Convert an audit severity into a SARIF level."""
        return {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }.get(severity, "warning")

    def _export_sbom(self):
        """Export a CycloneDX 1.5 SBOM of the scanned dependencies."""
        components = []
        # Collect the parsed dependencies (stored in dependency_stats via _audit_dependencies)
        # Re-parse the files to get the full data
        dep_files = self._find_dependency_files()
        parsers = {
            "requirements": self._parse_requirements_txt,
            "package_json": self._parse_package_json,
            "pom_xml": self._parse_pom_xml,
            "build_gradle": self._parse_build_gradle,
            "csproj": self._parse_csproj,
            "composer_json": self._parse_composer_json,
        }
        ecosystem_to_purl = {
            "PyPI": "pypi",
            "npm": "npm",
            "Maven": "maven",
            "NuGet": "nuget",
            "Packagist": "composer",
        }
        for dep_file, file_type in dep_files:
            parser = parsers.get(file_type)
            if not parser:
                continue
            for dep in parser(dep_file):
                purl_type = ecosystem_to_purl.get(dep["ecosystem"], "generic")
                version = dep.get("version") or "unknown"
                name = dep["name"]
                # Package URL (PURL)
                if ":" in name and purl_type == "maven":
                    group, artifact = name.split(":", 1)
                    purl = f"pkg:{purl_type}/{group}/{artifact}@{version}"
                else:
                    purl = f"pkg:{purl_type}/{name}@{version}"
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": purl,
                })

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": self.now.isoformat(),
                "tools": [{"name": self.tool_name, "version": self.config.get("project", {}).get("version", "1.0")}],
                "component": {
                    "type": "application",
                    "name": self.project_name,
                    "version": self.project_version,
                },
            },
            "components": components,
        }

        sbom_path = os.path.join(self.datas_dir, f"{self.brand_prefix}-SBOM-{self.timestamp}.json")
        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2, ensure_ascii=False)
        self._sbom_path = sbom_path

    def _cleanup_old_reports(self):
        """Clean up old reports according to the retention config."""
        retention = self.config.get("retention", {})
        mode = retention.get("mode")
        if not mode:
            logger.info("Retention: mode absent ou null, aucun nettoyage")
            return

        dry_run = self.config.get("_cli_options", {}).get("retention_dry_run", False)
        max_count = retention.get("max_count", 10)
        max_days = retention.get("max_days", 90)

        if dry_run:
            self.reporter.info(f"🧹 {self.t_console('retention_dry_run')}")
        else:
            self.reporter.info(f"🧹 {self.t_console('retention_cleanup')}")

        # Collect report+data pairs by timestamp
        # Patterns: {PREFIX}-REPORT-{ts}.html + {PREFIX}-DATA-{ts}.json
        current_prefix = self.brand_prefix
        legacy_prefix = "AUDIT"
        prefixes = [current_prefix]
        if legacy_prefix != current_prefix:
            prefixes.append(legacy_prefix)

        # Find all timestamps with their files
        timestamp_files = {}  # ts → {"html": path, "json": path}
        ts_pattern = re.compile(r'^(?:' + '|'.join(re.escape(p) for p in prefixes) + r')-REPORT-(\d{4}-\d{2}-\d{2}-\d{2}-\d{2})\.html$')

        if os.path.exists(self.reports_dir):
            for f in os.listdir(self.reports_dir):
                m = ts_pattern.match(f)
                if m:
                    ts = m.group(1)
                    if ts not in timestamp_files:
                        timestamp_files[ts] = {"html": None, "json": None}
                    timestamp_files[ts]["html"] = os.path.join(self.reports_dir, f)

        # Find the corresponding JSON files
        data_pattern = re.compile(r'^(?:' + '|'.join(re.escape(p) for p in prefixes) + r')-DATA-(\d{4}-\d{2}-\d{2}-\d{2}-\d{2})\.json$')
        if os.path.exists(self.datas_dir):
            for f in os.listdir(self.datas_dir):
                m = data_pattern.match(f)
                if m:
                    ts = m.group(1)
                    if ts not in timestamp_files:
                        timestamp_files[ts] = {"html": None, "json": None}
                    timestamp_files[ts]["json"] = os.path.join(self.datas_dir, f)

        if not timestamp_files:
            logger.info("Retention: aucun rapport trouvé")
            return

        # Sort by timestamp (oldest to most recent)
        sorted_ts = sorted(timestamp_files.keys())

        # Determine which timestamps to delete
        to_delete = set()

        if mode in ("count", "both"):
            if len(sorted_ts) > max_count:
                # Remove the oldest ones beyond max_count
                to_delete.update(sorted_ts[:len(sorted_ts) - max_count])

        if mode in ("days", "both"):
            cutoff = datetime.now() - timedelta(days=max_days)
            for ts in sorted_ts:
                try:
                    ts_dt = datetime.strptime(ts, "%Y-%m-%d-%H-%M")
                    if ts_dt < cutoff:
                        to_delete.add(ts)
                except ValueError:
                    continue

        # Safety net: always keep at least 1 report
        keep_count = len(sorted_ts) - len(to_delete)
        if keep_count < 1:
            # Remove the most recent one from the deletion list
            to_delete.discard(sorted_ts[-1])

        if not to_delete:
            logger.info(self.t_console("retention_skipped"))
            return

        # Delete the pairs
        deleted_count = 0
        for ts in sorted(to_delete):
            files = timestamp_files[ts]
            for ftype in ("html", "json"):
                fpath = files.get(ftype)
                if fpath and os.path.exists(fpath):
                    if dry_run:
                        self.reporter.step(self.t_console('retention_dry_run_file').format(filename=os.path.basename(fpath)), icon="📋")
                    else:
                        os.remove(fpath)
                        logger.detail(f"  Supprimé: {os.path.basename(fpath)}")
            deleted_count += 1

        if dry_run:
            self.reporter.info(f"  → {self.t_console('retention_dry_run_count').format(count=deleted_count)}")
        else:
            self.reporter.step(self.t_console('retention_deleted').format(count=deleted_count), icon="✅")

    def _compare_with_baseline(self, baseline_path: str):
        """Compare current results against a previous baseline."""
        if not os.path.exists(baseline_path):
            self.reporter.warn(f"{self.t_console('baseline_not_found')}: {baseline_path}")
            return

        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
        except Exception as e:
            self.reporter.warn(f"{self.t_console('baseline_read_error')}: {e}")
            return

        self.reporter.info(f"📊 {self.t_console('comparison_with')} {baseline_data.get('timestamp', 'N/A')}...")

        # Rebuild the baseline findings. Filter out auxiliary fields not
        # stored on Finding (e.g. `compliance`, added to the export for
        # consuming tools: SARIF, GitHub code-scanning) — otherwise
        # Finding(**fd) raises TypeError.
        _finding_fields = {f.name for f in fields(Finding)}
        baseline_list = []
        for fd in baseline_data.get("findings", []):
            clean_fd = {k: v for k, v in fd.items() if k in _finding_fields}
            baseline_list.append(Finding(**clean_fd))
        baseline_findings = self._index_findings(baseline_list)

        # Collect the current findings
        current_list = [f for cat in self.categories.values() for f in cat.findings]
        current_findings = self._index_findings(current_list)

        # Compute the differences
        baseline_keys = set(baseline_findings.keys())
        current_keys = set(current_findings.keys())

        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        unchanged_keys = current_keys & baseline_keys

        self.comparison = ComparisonResult(
            new_findings=[current_findings[k] for k in new_keys],
            resolved_findings=[baseline_findings[k] for k in resolved_keys],
            unchanged_findings=[current_findings[k] for k in unchanged_keys],
            baseline_date=baseline_data.get("timestamp", "N/A"),
            baseline_totals=baseline_data.get("totals", {}),
        )

        logger.info(self.t_console("log_comparison").format(new=len(new_keys), resolved=len(resolved_keys), unchanged=len(unchanged_keys)))

        # Display the summary
        self.reporter.info(f"  ➕ {self.t_console('new_issues')} : {len(self.comparison.new_findings)}")
        self.reporter.info(f"  ✅ {self.t_console('resolved_issues')} : {len(self.comparison.resolved_findings)}")
        self.reporter.info(f"  ⏸️  {self.t_console('persistent_issues')} : {len(self.comparison.unchanged_findings)}")
