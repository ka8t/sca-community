"""
Mixin dépendances — audit des vulnérabilités CVE via pip-audit / npm audit.
"""
import os
import re
import json
import glob
import logging
import subprocess
from typing import List, Dict, Optional, Tuple

from sca import SCRIPT_DIR

logger = logging.getLogger("sca.dependencies")


class AuditDependenciesMixin:
    """Dependency audit methods."""

    def _audit_dependencies(self):
        """Audit vulnerable dependencies via pip-audit / npm audit (local tools)."""
        # The [n/N] numbering and the icon are now emitted by
        # AuditRunner._run_phase via self.reporter.phase("dependencies").

        # Collect the dependency files in the target project
        dep_files = self._find_dependency_files()
        if not dep_files:
            logger.detail(self.t_console("log_no_dep_files"))
            return

        logger.detail(self.t_console("log_dep_files").format(files=[self._rel(f) for f, _ in dep_files]))

        # Parse the dependencies from each file
        all_deps = []
        parsers = {
            "requirements": self._parse_requirements_txt,
            "package_json": self._parse_package_json,
            "pom_xml": self._parse_pom_xml,
            "build_gradle": self._parse_build_gradle,
            "csproj": self._parse_csproj,
            "composer_json": self._parse_composer_json,
        }
        for dep_file, file_type in dep_files:
            parser = parsers.get(file_type)
            if parser:
                all_deps.extend(parser(dep_file))

        # Check for unpinned dependencies
        nb_unpinned = 0
        for dep in all_deps:
            if not dep.get("version"):
                nb_unpinned += 1
                self._add_rule_finding(
                    "DEPENDENCIES", "unpinned_dependency",
                    dep["file"], dep["line"],
                    dep["raw_line"], "HIGH",
                    confidence=90
                )

        # Check for vulnerabilities via local (optional) tools
        tools = self._check_dependency_tools()
        logger.detail(self.t_console("log_dep_tools").format(pip=bool(tools["pip_audit"]), npm=bool(tools["npm"])))
        vulns = []
        if tools["pip_audit"]:
            self.reporter.step(self.t_console("progress_pip_audit"), icon="🔍")
            vulns.extend(self._scan_with_pip_audit(dep_files, tools["pip_audit"]))
        if tools["npm"]:
            self.reporter.step(self.t_console("progress_npm_audit"), icon="🔍")
            vulns.extend(self._scan_with_npm_audit(dep_files, tools["npm"]))

        for vuln in vulns:
            severity = self._cvss_to_severity(vuln.get("cvss_score", 0))
            dep = vuln["dep"]
            vuln_ids = ", ".join(vuln.get("ids", [])[:3])
            fix_versions = ", ".join(vuln.get("fix_versions", [])[:3])
            code = f"{dep['name']}=={dep['version']} ({vuln_ids})"
            fix_suggestion = f"Mettre à jour vers : {fix_versions}" if fix_versions else ""
            self._add_rule_finding(
                "DEPENDENCIES", "vulnerable_dependency",
                dep["file"], dep["line"],
                code, severity,
                confidence=95,
                fix_suggestion=fix_suggestion
            )

        # Check licenses (if the licenses.allowed config is set)
        nb_license_issues = self._check_licenses(dep_files)

        # Store the statistics for the HTML report
        nb_vulnerable = len(vulns)
        nb_ok = max(0, len(all_deps) - nb_vulnerable - nb_unpinned)
        self.dependency_stats = {
            "total_scanned": len(all_deps),
            "vulnerable": nb_vulnerable,
            "unpinned": nb_unpinned,
            "ok": nb_ok,
            "warnings": self.dependency_warnings,
        }

        logger.info(self.t_console("log_dep_summary").format(scanned=len(all_deps), vuln=nb_vulnerable, unpinned=nb_unpinned))

    def _find_dependency_files(self) -> List[Tuple[str, str]]:
        """Find dependency manifest files in the target project."""
        dep_files = []
        seen = set()

        # File → type mapping
        root_files = {
            "requirements.txt": "requirements",
            "pyproject.toml": "requirements",
            "pom.xml": "pom_xml",
            "build.gradle": "build_gradle",
            "composer.json": "composer_json",
        }
        root_globs = {
            "requirements/*.txt": "requirements",
            "*.csproj": "csproj",
        }

        # Look at the project root
        # NB: seen stores normalized paths (os.path.normpath) — otherwise
        # "root_dir/requirements.txt" and "root_dir/./requirements.txt"
        # (the latter produced by include_paths=["."], the default value
        # of every generated audit.config.json) are two different strings
        # for the same file, and the SBOM lists each dependency twice.
        for filename, file_type in root_files.items():
            filepath = os.path.normpath(os.path.join(self.root_dir, filename))
            if os.path.exists(filepath) and filepath not in seen:
                dep_files.append((filepath, file_type))
                seen.add(filepath)
        for pattern, file_type in root_globs.items():
            for match in glob.glob(os.path.join(self.root_dir, pattern)):
                match = os.path.normpath(match)
                if match not in seen:
                    dep_files.append((match, file_type))
                    seen.add(match)

        # Look in the include paths
        for base_path in self.include_paths:
            full_path = os.path.join(self.root_dir, base_path)
            if not os.path.exists(full_path):
                continue

            for filename, file_type in root_files.items():
                filepath = os.path.normpath(os.path.join(full_path, filename))
                if os.path.exists(filepath) and filepath not in seen:
                    dep_files.append((filepath, file_type))
                    seen.add(filepath)
            for pattern, file_type in root_globs.items():
                for match in glob.glob(os.path.join(full_path, pattern)):
                    match = os.path.normpath(match)
                    if match not in seen:
                        dep_files.append((match, file_type))
                        seen.add(match)

            # package.json (JS — already in root_files, but also in subdirectories)
            pkg_json = os.path.normpath(os.path.join(full_path, "package.json"))
            if os.path.exists(pkg_json) and pkg_json not in seen:
                dep_files.append((pkg_json, "package_json"))
                seen.add(pkg_json)

        return dep_files

    def _parse_requirements_txt(self, filepath: str) -> List[dict]:
        """Parse a requirements.txt file and return its dependencies."""
        deps = []

        # Handle pyproject.toml — simplified extraction of the dependencies
        if filepath.endswith("pyproject.toml"):
            return self._parse_pyproject_toml(filepath)

        for line_num, line_content in self._read_file(filepath):
            line_stripped = line_content.strip()
            # Ignore comments and blank lines
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("-"):
                continue
            # Pattern: package==version, package>=version, package~=version, package<=version
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*==\s*([0-9][0-9a-zA-Z.*]*)', line_stripped)
            if match:
                deps.append({
                    "name": match.group(1).lower(),
                    "version": match.group(2),
                    "ecosystem": "PyPI",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": line_stripped,
                })
            else:
                # Dependency without an exact version (>=, ~=, no version)
                match_name = re.match(r'^([a-zA-Z0-9_.-]+)', line_stripped)
                if match_name:
                    # Extract the version if present (>=, ~=, <=)
                    ver_match = re.search(r'[>=~<]+\s*([0-9][0-9a-zA-Z.*]*)', line_stripped)
                    deps.append({
                        "name": match_name.group(1).lower(),
                        "version": ver_match.group(1) if ver_match else None,
                        "ecosystem": "PyPI",
                        "file": filepath,
                        "line": line_num,
                        "raw_line": line_stripped,
                    })
        return deps

    def _parse_pyproject_toml(self, filepath: str) -> List[dict]:
        """Parse dependencies from pyproject.toml (the [project] dependencies section)."""
        deps = []
        in_deps_section = False
        for line_num, line_content in self._read_file(filepath):
            line_stripped = line_content.strip()
            # Detect the dependencies = [ section
            if re.match(r'^dependencies\s*=\s*\[', line_stripped):
                in_deps_section = True
                continue
            if in_deps_section:
                if line_stripped == "]":
                    in_deps_section = False
                    continue
                # Extract "package>=version" or "package==version"
                match = re.match(r'^\s*"([a-zA-Z0-9_.-]+)\s*(==|>=|~=|<=)\s*([0-9][0-9a-zA-Z.*]*)', line_stripped)
                if match:
                    version = match.group(3) if match.group(2) == "==" else match.group(3)
                    is_pinned = match.group(2) == "=="
                    deps.append({
                        "name": match.group(1).lower(),
                        "version": version,
                        "ecosystem": "PyPI",
                        "file": filepath,
                        "line": line_num,
                        "raw_line": line_stripped.strip('",').strip(),
                    })
                    if not is_pinned:
                        # Not pinned — keep the version for the local scan
                        # but also flag it as unpinned
                        pass
                elif re.match(r'^\s*"([a-zA-Z0-9_.-]+)"', line_stripped):
                    # Dependency without a version
                    name_match = re.match(r'^\s*"([a-zA-Z0-9_.-]+)"', line_stripped)
                    if name_match:
                        deps.append({
                            "name": name_match.group(1).lower(),
                            "version": None,
                            "ecosystem": "PyPI",
                            "file": filepath,
                            "line": line_num,
                            "raw_line": line_stripped.strip('",').strip(),
                        })
        return deps

    def _parse_package_json(self, filepath: str) -> List[dict]:
        """Parse a package.json file and return its dependencies."""
        deps = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                pkg = json.load(f)
        except (json.JSONDecodeError, OSError):
            return deps

        # Read the file line by line to get line numbers
        lines = self._read_file(filepath)
        line_map = {}
        for line_num, line_content in lines:
            # Look for "package": "version"
            match = re.search(r'"([^"]+)"\s*:\s*"([^"]*)"', line_content)
            if match:
                line_map[match.group(1)] = line_num

        for section in ["dependencies", "devDependencies"]:
            section_deps = pkg.get(section, {})
            if not isinstance(section_deps, dict):
                continue
            for name, version_spec in section_deps.items():
                # Strip the version prefix: ^1.2.3 → 1.2.3, ~1.2.3 → 1.2.3
                clean_version = re.sub(r'^[\^~>=<]*', '', str(version_spec)).strip()
                is_pinned = bool(re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$', clean_version))
                line_num = line_map.get(name, 0)
                raw_line = f'"{name}": "{version_spec}"'
                deps.append({
                    "name": name,
                    "version": clean_version if clean_version and clean_version[0].isdigit() else None,
                    "ecosystem": "npm",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": raw_line,
                })
        return deps

    def _check_licenses(self, dep_files: List[Tuple[str, str]]) -> int:
        """Check package license compliance against the allowed SPDX list."""
        allowed = self.config.get("licenses", {}).get("allowed", [])
        if not allowed:
            return 0

        allowed_upper = [l.upper() for l in allowed]
        nb_issues = 0

        for dep_file, file_type in dep_files:
            if file_type == "package_json":
                try:
                    with open(dep_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    # The package's own license
                    license_val = data.get("license", "")
                    if license_val and str(license_val).upper() not in allowed_upper:
                        self._add_rule_finding(
                            "DEPENDENCIES", "non_compliant_license",
                            dep_file, 1,
                            f"license: {license_val}", "MEDIUM",
                            confidence=80
                        )
                        nb_issues += 1
                except (json.JSONDecodeError, OSError):
                    pass
            elif file_type == "composer_json":
                try:
                    with open(dep_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    license_val = data.get("license", "")
                    if license_val and str(license_val).upper() not in allowed_upper:
                        self._add_rule_finding(
                            "DEPENDENCIES", "non_compliant_license",
                            dep_file, 1,
                            f"license: {license_val}", "MEDIUM",
                            confidence=80
                        )
                        nb_issues += 1
                except (json.JSONDecodeError, OSError):
                    pass
        return nb_issues

    def _parse_pom_xml(self, filepath: str) -> List[dict]:
        """Parse a Maven pom.xml and return its dependencies (regex-based, no XML parser)."""
        deps = []
        content = ""
        lines_data = self._read_file(filepath)
        for _, line_content in lines_data:
            content += line_content + "\n"

        # Extract each <dependency>...</dependency>
        dep_blocks = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
        for block in dep_blocks:
            group_id = re.search(r'<groupId>(.*?)</groupId>', block)
            artifact_id = re.search(r'<artifactId>(.*?)</artifactId>', block)
            version_match = re.search(r'<version>(.*?)</version>', block)
            if not artifact_id:
                continue
            name = f"{group_id.group(1)}:{artifact_id.group(1)}" if group_id else artifact_id.group(1)
            version = version_match.group(1).strip() if version_match else None

            # Look for the line number of this artifactId
            line_num = 0
            aid_text = artifact_id.group(1)
            for ln, lc in lines_data:
                if aid_text in lc:
                    line_num = ln
                    break

            # Version considered unpinned if:
            # - absent, placeholder ${...}, LATEST, RELEASE, range [x,y), or wildcard *
            is_pinned = bool(version and
                             re.match(r'^[0-9][0-9a-zA-Z._-]*$', version) and
                             '${' not in version)
            deps.append({
                "name": name,
                "version": version if is_pinned else None,
                "ecosystem": "Maven",
                "file": filepath,
                "line": line_num,
                "raw_line": f"{name} {version or '(no version)'}",
            })
        return deps

    def _parse_build_gradle(self, filepath: str) -> List[dict]:
        """Parse a build.gradle file and return its dependencies."""
        deps = []
        for line_num, line_content in self._read_file(filepath):
            line_stripped = line_content.strip()
            # Pattern: implementation 'group:artifact:version'
            match = re.search(
                r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['\"]([^'\"]+:[^'\"]+):([^'\"]+)['\"]",
                line_stripped
            )
            if match:
                name = match.group(1)
                version = match.group(2).strip()
                is_pinned = bool(re.match(r'^[0-9][0-9a-zA-Z._-]*$', version))
                deps.append({
                    "name": name,
                    "version": version if is_pinned else None,
                    "ecosystem": "Maven",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": line_stripped,
                })
                continue
            # Pattern: implementation("group:artifact:version")
            match = re.search(
                r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*"([^"]+:[^"]+):([^"]+)"',
                line_stripped
            )
            if match:
                name = match.group(1)
                version = match.group(2).strip()
                is_pinned = bool(re.match(r'^[0-9][0-9a-zA-Z._-]*$', version))
                deps.append({
                    "name": name,
                    "version": version if is_pinned else None,
                    "ecosystem": "Maven",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": line_stripped,
                })
        return deps

    def _parse_csproj(self, filepath: str) -> List[dict]:
        """Parse a .csproj file and return its PackageReference entries."""
        deps = []
        for line_num, line_content in self._read_file(filepath):
            # Pattern: <PackageReference Include="Name" Version="1.2.3" />
            match = re.search(
                r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]*)")?',
                line_content
            )
            if match:
                name = match.group(1)
                version = match.group(2).strip() if match.group(2) else None
                # Pinned version = purely numeric (no wildcard *, no range [,])
                is_pinned = bool(version and
                                 re.match(r'^[0-9]+\.[0-9]+[0-9a-zA-Z._-]*$', version) and
                                 '*' not in version and '[' not in version)
                deps.append({
                    "name": name,
                    "version": version if is_pinned else None,
                    "ecosystem": "NuGet",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": line_content.strip(),
                })
        return deps

    def _parse_composer_json(self, filepath: str) -> List[dict]:
        """Parse a composer.json file and return its dependencies."""
        deps = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return deps

        # Read the file line by line to get line numbers
        lines = self._read_file(filepath)
        line_map = {}
        for line_num, line_content in lines:
            match = re.search(r'"([^"]+)"\s*:\s*"([^"]*)"', line_content)
            if match:
                line_map[match.group(1)] = line_num

        for section in ["require", "require-dev"]:
            section_deps = data.get(section, {})
            if not isinstance(section_deps, dict):
                continue
            for name, version_spec in section_deps.items():
                # Ignore "php" and "ext-*" (not packages)
                if name == "php" or name.startswith("ext-"):
                    continue
                clean_version = re.sub(r'^[\^~>=<|]*', '', str(version_spec)).strip()
                is_pinned = bool(re.match(r'^[0-9]+\.[0-9]+\.[0-9]+$', clean_version))
                line_num = line_map.get(name, 0)
                deps.append({
                    "name": name,
                    "version": clean_version if is_pinned else None,
                    "ecosystem": "Packagist",
                    "file": filepath,
                    "line": line_num,
                    "raw_line": f'"{name}": "{version_spec}"',
                })
        return deps

    def _check_dependency_tools(self) -> dict:
        """Check the availability of optional CVE scanning tools (pip-audit, npm)."""
        import shutil
        tools = {"pip_audit": None, "npm": None}
        # Look for pip-audit in the audit script's .venv (based on SCRIPT_DIR)
        venv_bin = os.path.join(str(SCRIPT_DIR), ".venv", "bin")
        pip_audit_in_venv = os.path.join(venv_bin, "pip-audit")
        if os.path.isfile(pip_audit_in_venv):
            tools["pip_audit"] = pip_audit_in_venv
        else:
            # Fallback: look in the system PATH
            tools["pip_audit"] = shutil.which("pip-audit")
        if not tools["pip_audit"]:
            venv_pip = os.path.join(venv_bin, "pip")
            install_cmd = f"{venv_pip} install pip-audit"
            self.reporter.warn(f"{self.t_console('pip_audit_not_found')} : {install_cmd}")
            self.dependency_warnings.append({
                "tool": "pip-audit",
                "type": "tool_missing",
                "message": f"{self.t_console('pip_audit_not_found')} : {install_cmd}",
            })
        npm_path = shutil.which("npm")
        tools["npm"] = npm_path
        if not tools["npm"]:
            install_cmd = "brew install node (macOS) / https://nodejs.org"
            self.reporter.warn(f"{self.t_console('npm_not_found')} : {install_cmd}")
            self.dependency_warnings.append({
                "tool": "npm",
                "type": "tool_missing",
                "message": f"{self.t_console('npm_not_found')} : {install_cmd}",
            })
        return tools

    def _scan_with_pip_audit(self, dep_files: List[Tuple[str, str]], pip_audit_path: str) -> List[dict]:
        """Scan Python dependencies via pip-audit (installed in the .venv)."""
        vulns = []
        req_files = [f for f, t in dep_files if t == "requirements"]
        for filepath in req_files:
            try:
                # pip-audit -r requirements.txt --format json
                cmd = [pip_audit_path, "--format", "json", "-r", filepath]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                # pip-audit returns exit code 1 when vulnerabilities are found, which is normal
                if result.stdout:
                    data = json.loads(result.stdout)
                    # Format: {"dependencies": [{"name": ..., "version": ..., "vulns": [...]}]}
                    # or directly a list depending on the version
                    deps_list = data if isinstance(data, list) else data.get("dependencies", [])
                    for dep_info in deps_list:
                        for v in dep_info.get("vulns", []):
                            vuln_id = v.get("id", "")
                            fix_versions = v.get("fix_versions", [])
                            aliases = v.get("aliases", [])
                            ids = [vuln_id] + aliases[:2]
                            # Look for the line in the source file
                            line_num = self._find_dep_line(filepath, dep_info["name"])
                            vulns.append({
                                "dep": {
                                    "name": dep_info["name"],
                                    "version": dep_info.get("version", ""),
                                    "file": filepath,
                                    "line": line_num,
                                },
                                "ids": ids,
                                "cvss_score": self._severity_text_to_cvss(v.get("description", "")),
                                "fix_versions": fix_versions,
                            })
                elif result.stderr:
                    # pip-audit failed — capture the errors
                    stderr_lines = [l.strip() for l in result.stderr.strip().splitlines() if l.strip()]
                    # Filter: keep short, relevant ERROR lines (< 200 chars)
                    error_lines = [l for l in stderr_lines
                                   if "ERROR" in l and "pip_audit" not in l and len(l) < 200]
                    if not error_lines:
                        # Last line if no short error was found
                        error_lines = [stderr_lines[-1][:200]] if stderr_lines else ["Unknown error"]
                    error_msg = " | ".join(error_lines[:3])
                    self.dependency_warnings.append({
                        "tool": "pip-audit",
                        "type": "scan_error",
                        "file": filepath,
                        "message": error_msg,
                    })
            except subprocess.TimeoutExpired:
                self.dependency_warnings.append({
                    "tool": "pip-audit", "type": "scan_error", "file": filepath,
                    "message": "Timeout (120s)",
                })
            except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
                self.dependency_warnings.append({
                    "tool": "pip-audit", "type": "scan_error", "file": filepath,
                    "message": str(e),
                })
        return vulns

    def _scan_with_npm_audit(self, dep_files: List[Tuple[str, str]], npm_path: str) -> List[dict]:
        """Scan JavaScript dependencies via npm audit."""
        vulns = []
        pkg_files = [f for f, t in dep_files if t == "package_json"]
        for filepath in pkg_files:
            try:
                pkg_dir = os.path.dirname(filepath)
                # npm audit requires a node_modules or package-lock.json
                # We attempt it anyway — npm handles the errors
                cmd = [npm_path, "audit", "--json"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=pkg_dir, timeout=120)
                if result.stdout:
                    data = json.loads(result.stdout)
                    # npm audit format: {"vulnerabilities": {"pkg_name": {"severity": ..., "via": [...]}}}
                    for pkg_name, info in data.get("vulnerabilities", {}).items():
                        severity_text = info.get("severity", "moderate").upper()
                        # Extract the CVE/advisory IDs from via
                        ids = []
                        fix_version = info.get("fixAvailable", {})
                        fix_versions = []
                        if isinstance(fix_version, dict):
                            v = fix_version.get("version", "")
                            if v:
                                fix_versions = [v]
                        for via_item in info.get("via", []):
                            if isinstance(via_item, dict):
                                url = via_item.get("url", "")
                                if url:
                                    ids.append(url.split("/")[-1])
                        if not ids:
                            ids = [f"npm-advisory-{pkg_name}"]
                        line_num = self._find_dep_line(filepath, pkg_name)
                        vulns.append({
                            "dep": {
                                "name": pkg_name,
                                "version": info.get("range", ""),
                                "file": filepath,
                                "line": line_num,
                            },
                            "ids": ids[:3],
                            "cvss_score": {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}.get(severity_text, 5.5),
                            "fix_versions": fix_versions,
                        })
                elif result.stderr:
                    stderr_lines = [l.strip() for l in result.stderr.strip().splitlines() if l.strip()]
                    error_msg = " | ".join(stderr_lines[-3:])
                    self.dependency_warnings.append({
                        "tool": "npm audit",
                        "type": "scan_error",
                        "file": filepath,
                        "message": error_msg,
                    })
            except subprocess.TimeoutExpired:
                self.dependency_warnings.append({
                    "tool": "npm audit", "type": "scan_error", "file": filepath,
                    "message": "Timeout (120s)",
                })
            except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
                self.dependency_warnings.append({
                    "tool": "npm audit", "type": "scan_error", "file": filepath,
                    "message": str(e),
                })
        return vulns

    def _find_dep_line(self, filepath: str, dep_name: str) -> int:
        """Find the line number of a dependency within a file."""
        for line_num, line_content in self._read_file(filepath):
            if dep_name.lower() in line_content.lower():
                return line_num
        return 0

    def _severity_text_to_cvss(self, description: str) -> float:
        """Convert a textual severity description to an approximate CVSS score."""
        desc_upper = description.upper()
        if "CRITICAL" in desc_upper:
            return 9.5
        elif "HIGH" in desc_upper:
            return 8.0
        elif "MODERATE" in desc_upper or "MEDIUM" in desc_upper:
            return 5.5
        elif "LOW" in desc_upper:
            return 2.5
        return 7.0  # Default to HIGH if unknown

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Convert a CVSS score to an audit severity level."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "MEDIUM"  # Fallback if score is unknown
