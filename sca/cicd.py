"""
CI/CD — audits GitHub Actions and GitLab CI/CD workflows.
Detects supply-chain vulnerabilities in pipelines.
"""
import os
import re
import logging

logger = logging.getLogger("sca.cicd")


class AuditCICDMixin:
    """Methods for auditing CI/CD workflows."""

    def _audit_cicd(self):
        """Audit CI/CD workflow files (GitHub Actions, GitLab CI).

        Note: currently not called by AuditRunner.run() — CI/CD detection
        goes through the rule engine (.sca YAML) instead.
        """
        yaml_files = self._find_files(self._yaml_exts, self._yaml_paths)
        if not yaml_files:
            self.categories["CICD"].successes.append(self.t_console("no_cicd_files"))
            return

        self.cicd_stats = {"files_scanned": len(yaml_files), "findings": 0}

        for file_path in yaml_files:
            raw = self._read_file(file_path)
            if not raw:
                continue
            # _read_file returns [(num, line), ...] — extract the content
            lines = [line.rstrip("\n") for _, line in raw]
            content = "\n".join(lines)

            self._check_pull_request_target_checkout(file_path, lines)
            self._check_gha_expression_injection(file_path, lines)
            self._check_gha_excessive_permissions(file_path, lines)
            self._check_gha_missing_permissions(file_path, content, lines)
            self._check_gha_unguarded_comment_trigger(file_path, content, lines)
            self._check_unpinned_action_version(file_path, lines)
            self._check_gitlab_unsafe_variables(file_path, lines)
            self._check_workflow_not_in_codeowners(file_path)
            self._check_gha_secret_in_log(file_path, lines)
            self._check_gha_deprecated_commands(file_path, lines)
            self._check_gha_artifact_poisoning(file_path, content, lines)
            self._check_gha_self_hosted_runner(file_path, lines)
            self._check_ci_curl_pipe_bash(file_path, lines)
            self._check_ci_insecure_download(file_path, lines)
            self._check_hardcoded_secret_cicd(file_path, lines)
            self._check_docker_latest_tag(file_path, lines)
            self._check_gitlab_allow_failure_security(file_path, content, lines)
            self._check_gitlab_script_secrets_echo(file_path, lines)
            self._check_gha_credentials_on_disk(file_path, lines)
            self._check_gha_github_env_write(file_path, lines)
            self._check_ci_docker_privileged(file_path, lines)
            self._check_gha_dangerous_artefact(file_path, content, lines)
            self._check_gha_insecure_commands_env(file_path, lines)
            self._check_gha_cache_poisoning(file_path, content, lines)
            self._check_dependabot_insecure_exec(file_path, lines)
            self._check_gha_github_app_no_revoke(file_path, lines)
            self._check_gha_confused_deputy(file_path, content, lines)
            self._check_gha_job_all_secrets(file_path, lines)
            self._check_ci_netcat_reverse_shell(file_path, lines)
            self._check_gha_secrets_bypass_redaction(file_path, lines)
            self._check_gha_actor_check_bypass(file_path, lines)
            self._check_ci_debug_trace_enabled(file_path, lines)
            self._check_gha_secrets_without_environment(file_path, content)
            self._check_gha_unsound_condition(file_path, lines)
            self._check_gha_workflow_dispatch_inputs(file_path, content, lines)
            self._check_gha_version_comment_missing(file_path, lines)
            self._check_gha_local_action(file_path, lines)
            self._check_gitlab_double_pipeline(file_path, lines)


        self.cicd_stats["findings"] = len(self.categories["CICD"].findings)

    # =========================================================================
    # CI/CD RULES
    # =========================================================================

    def _check_pull_request_target_checkout(self, file_path, lines):
        """Detect pull_request_target with fork checkout (HIGH, OWASP CI-CD-01)."""
        r = self._rule("pull_request_target_checkout")
        if not r:
            return

        has_prt = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "pull_request_target" in stripped and not stripped.startswith("#"):
                has_prt = True
                break

        if not has_prt:
            return

        # Look for a checkout with the PR's ref (dangerous with pull_request_target)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Detect checkout with github.event.pull_request.head.ref/sha
            if "actions/checkout" in stripped:
                # Check the following lines for ref:
                for j in range(i + 1, min(i + 8, len(lines))):
                    ref_line = lines[j].strip()
                    if ref_line.startswith("#"):
                        continue
                    if "ref:" in ref_line and ("pull_request" in ref_line or "head" in ref_line or "github.event" in ref_line):
                        code = lines[i].strip()
                        self._add_finding(
                            "CICD", r["name"], file_path, i + 1, code,
                            "HIGH", r["risk"], r["solution"], r["benefit"],
                            confidence=85, rule_key="pull_request_target_checkout"
                        )
                        return

    def _check_gha_expression_injection(self, file_path, lines):
        """Detect ${{ }} interpolation inside run: blocks (HIGH, OWASP CI-CD-01)."""
        r = self._rule("gha_expression_injection")
        if not r:
            return

        # Dangerous patterns: user-controlled data inside ${{ }}
        dangerous_contexts = [
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.discussion.title",
            "github.event.discussion.body",
            "github.head_ref",
            "github.event.workflow_run.head_branch",
        ]

        in_run_block = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Detect the start of a run: block
            if re.match(r"run\s*:\s*[|>]?\s*$", stripped) or re.match(r"run\s*:\s*\S", stripped):
                in_run_block = True
            elif stripped and not stripped.startswith("-") and ":" in stripped and not stripped.startswith("$"):
                # New YAML key — end of the run block
                if in_run_block and not line.startswith(" " * 8) and not line.startswith("\t\t"):
                    in_run_block = False

            if in_run_block or (stripped.startswith("run:") and "${{" in stripped):
                for ctx in dangerous_contexts:
                    if ctx in stripped:
                        self._add_finding(
                            "CICD", r["name"], file_path, i + 1, stripped,
                            "HIGH", r["risk"], r["solution"], r["benefit"],
                            confidence=90, rule_key="gha_expression_injection"
                        )
                        return

    def _check_gha_excessive_permissions(self, file_path, lines):
        """Detect excessive write-all permissions (MEDIUM, OWASP CI-CD-05)."""
        r = self._rule("gha_excessive_permissions")
        if not r:
            return

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"permissions\s*:\s*write-all", stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="gha_excessive_permissions"
                )
                return

    def _check_gha_missing_permissions(self, file_path, content, lines):
        """Detect workflows without an explicit permissions: block (MEDIUM, OWASP CI-CD-05)."""
        r = self._rule("gha_missing_permissions")
        if not r:
            return

        # Only for GitHub Actions files (contain 'on:' and 'jobs:')
        if "jobs:" not in content:
            return
        # Check for the 'on:' trigger
        has_on_trigger = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"on\s*:", stripped) or stripped == "on:":
                has_on_trigger = True
                break
        if not has_on_trigger:
            return

        # Look for 'permissions:' at the top level
        has_permissions = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.match(r"permissions\s*:", stripped):
                has_permissions = True
                break

        if not has_permissions:
            self._add_finding(
                "CICD", r["name"], file_path, 1, "# (no permissions block)",
                "MEDIUM", r["risk"], r["solution"], r["benefit"],
                confidence=75, rule_key="gha_missing_permissions"
            )

    def _check_gha_unguarded_comment_trigger(self, file_path, content, lines):
        """Detect issue_comment trigger without an author_association check (MEDIUM)."""
        r = self._rule("gha_unguarded_comment_trigger")
        if not r:
            return

        has_comment_trigger = False
        trigger_line = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "issue_comment" in stripped:
                has_comment_trigger = True
                trigger_line = i
                break

        if not has_comment_trigger:
            return

        # Check whether author_association is used anywhere
        if "author_association" not in content:
            self._add_finding(
                "CICD", r["name"], file_path, trigger_line + 1,
                lines[trigger_line].strip(),
                "MEDIUM", r["risk"], r["solution"], r["benefit"],
                confidence=70, rule_key="gha_unguarded_comment_trigger"
            )

    def _check_unpinned_action_version(self, file_path, lines):
        """Detect actions not pinned by SHA (HIGH, OWASP CI-CD-09)."""
        r = self._rule("unpinned_action_version")
        if not r:
            return

        # Pattern: uses: owner/action@ref (where ref is not a 40-char SHA)
        uses_pattern = re.compile(r"uses\s*:\s*([^@\s]+)@(\S+)")
        sha_pattern = re.compile(r"^[0-9a-f]{40}$")

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = uses_pattern.search(stripped)
            if match:
                action_name = match.group(1)
                ref = match.group(2)
                # Ignore local actions (./)
                if action_name.startswith("./"):
                    continue
                # Check whether the ref is a SHA
                if not sha_pattern.match(ref):
                    # Check whether it's a mutable tag (main, master, v1, etc.)
                    if ref in ("main", "master", "develop") or re.match(r"^v\d+$", ref):
                        self._add_finding(
                            "CICD", r["name"], file_path, i + 1, stripped,
                            "HIGH", r["risk"], r["solution"], r["benefit"],
                            confidence=85, rule_key="unpinned_action_version"
                        )
                        return

    def _check_gitlab_unsafe_variables(self, file_path, lines):
        """Detect usage of untrusted GitLab CI variables (MEDIUM).

        Targets: $CI_COMMIT_REF_NAME, $CI_MERGE_REQUEST_TITLE, $CI_COMMIT_MESSAGE
        in scripts — command injection vectors.
        """
        r = self._rule("gitlab_unsafe_variables")
        if not r:
            return

        # Check that it's a GitLab CI file
        content_joined = "\n".join(lines[:30])
        is_gitlab = any(kw in content_joined for kw in ["stages:", "image:", ".gitlab-ci"])
        if not is_gitlab and ".gitlab-ci" not in file_path:
            return

        unsafe_vars = re.compile(
            r"\$CI_COMMIT_REF_NAME|\$CI_MERGE_REQUEST_TITLE|\$CI_COMMIT_MESSAGE"
        )

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if unsafe_vars.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=70, rule_key="gitlab_unsafe_variables"
                )
                return

    def _check_gha_secret_in_log(self, file_path, lines):
        """Detect GitHub Actions secrets echoed into logs (HIGH)."""
        r = self._rule("gha_secret_in_log")
        if not r:
            return

        pattern = re.compile(r"echo[^#\n]*\$\{\{[^}]*secrets\.", re.IGNORECASE)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gha_secret_in_log"
                )
                return

    def _check_gha_deprecated_commands(self, file_path, lines):
        """Detect deprecated workflow commands ::set-env:: and ::add-path:: (HIGH)."""
        r = self._rule("gha_deprecated_commands")
        if not r:
            return

        pattern = re.compile(r"::(?:set-env\s*name=|add-path)::")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="gha_deprecated_commands"
                )
                return

    def _check_gha_artifact_poisoning(self, file_path, content, lines):
        """Detect workflow_run + download-artifact without integrity verification (MEDIUM)."""
        r = self._rule("gha_artifact_poisoning")
        if not r:
            return

        if "workflow_run" not in content or "download-artifact" not in content:
            return

        for i, line in enumerate(lines):
            stripped = line.strip()
            if "workflow_run" in stripped and not stripped.startswith("#"):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=75, rule_key="gha_artifact_poisoning"
                )
                return

    def _check_gha_self_hosted_runner(self, file_path, lines):
        """Detect self-hosted runners (MEDIUM, OWASP CI-CD-06)."""
        r = self._rule("gha_self_hosted_runner")
        if not r:
            return

        pattern = re.compile(r"runs-on\s*:\s*\[?\s*self-hosted")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=80, rule_key="gha_self_hosted_runner"
                )
                return

    def _check_ci_curl_pipe_bash(self, file_path, lines):
        """Detect curl|wget piped into a shell (HIGH, OWASP CI-CD-09)."""
        r = self._rule("ci_curl_pipe_bash")
        if not r:
            return

        pattern = re.compile(r"(?:curl|wget)\b[^|\n#]*\|\s*(?:ba)?sh\b")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="ci_curl_pipe_bash"
                )
                return

    def _check_ci_insecure_download(self, file_path, lines):
        """Detect unencrypted HTTP downloads in CI/CD (MEDIUM)."""
        r = self._rule("ci_insecure_download")
        if not r:
            return

        pattern = re.compile(r"(?:curl|wget)\s+['\"]?http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=85, rule_key="ci_insecure_download"
                )
                return

    def _check_hardcoded_secret_cicd(self, file_path, lines):
        """Detect hardcoded secrets in CI/CD files (CRITICAL, OWASP CI-CD-04)."""
        r = self._rule("hardcoded_secret_cicd")
        if not r:
            return

        key_pattern = re.compile(
            r"(?:password|token|api[_-]?key|secret[_-]?key|access[_-]?key|private[_-]?key)\s*:\s*[\"']?(?!\$\{|\{\{)([A-Za-z0-9+/\-_@!]{16,})[\"']?",
            re.IGNORECASE
        )
        placeholder_pattern = re.compile(
            r"(?i)(?:example|placeholder|dummy|change[_-]?me|your[_-]|xxx+|redacted|replace|todo|fixme|changeit)",
        )

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = key_pattern.search(stripped)
            if match:
                value = match.group(1)
                if not placeholder_pattern.search(value) and not placeholder_pattern.search(stripped):
                    self._add_finding(
                        "CICD", r["name"], file_path, i + 1, stripped,
                        "CRITICAL", r["risk"], r["solution"], r["benefit"],
                        confidence=80, rule_key="hardcoded_secret_cicd"
                    )
                    return

    def _check_docker_latest_tag(self, file_path, lines):
        """Detect Docker images using the :latest tag in CI/CD (LOW)."""
        r = self._rule("docker_latest_tag")
        if not r:
            return

        pattern = re.compile(r"image\s*:\s*\S+:latest\b")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "LOW", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="docker_latest_tag"
                )
                return

    def _check_gitlab_allow_failure_security(self, file_path, content, lines):
        """Detect allow_failure: true on GitLab CI security jobs (HIGH).

        Analyzes block by block: only jobs whose name matches a known
        security tool are flagged, to avoid false positives.
        """
        r = self._rule("gitlab_allow_failure_security")
        if not r:
            return

        security_name = re.compile(
            r"(?:sast|dast|secret[_-]?detection|dependency[_-]?scanning|security[_-]?scan|bandit|trivy|snyk|semgrep|gitleaks|sonarqube|sonar)",
            re.IGNORECASE
        )
        allow_failure_pattern = re.compile(r"allow_failure\s*:\s*true")
        top_level_key = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-\.]*\s*:")

        in_security_job = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Detect a top-level job (no indentation)
            if not line.startswith((" ", "\t")) and top_level_key.match(line):
                job_name = line.split(":")[0].strip()
                in_security_job = bool(security_name.search(job_name))
            # Check allow_failure within a security job block
            if in_security_job and allow_failure_pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=85, rule_key="gitlab_allow_failure_security"
                )
                return

    def _check_gitlab_script_secrets_echo(self, file_path, lines):
        """Detect GitLab CI auth tokens echoed into logs (HIGH)."""
        r = self._rule("gitlab_script_secrets_echo")
        if not r:
            return

        pattern = re.compile(
            r"echo\s+[^#\n]*(?:\$CI_JOB_TOKEN|\$GITLAB_TOKEN|\$CI_REGISTRY_PASSWORD|\$CI_DEPLOY_TOKEN|\$CI_DEPLOY_PASSWORD)"
        )
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gitlab_script_secrets_echo"
                )
                return

    def _check_gha_insecure_commands_env(self, file_path, lines):
        """Detect ACTIONS_ALLOW_UNSECURE_COMMANDS: true (HIGH, CVE-2020-15228)."""
        r = self._rule("gha_insecure_commands_env")
        if not r:
            return
        pattern = re.compile(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*true", re.IGNORECASE)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="gha_insecure_commands_env"
                )
                return

    def _check_gha_cache_poisoning(self, file_path, content, lines):
        """Detect cache usage on a release trigger (HIGH, OWASP CI-CD-09)."""
        r = self._rule("gha_cache_poisoning")
        if not r:
            return
        if "release" not in content:
            return
        cache_pattern = re.compile(r"(?:actions/cache@|cache:\s*true)")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if cache_pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=75, rule_key="gha_cache_poisoning"
                )
                return

    def _check_dependabot_insecure_exec(self, file_path, lines):
        """Detect insecure-external-code-execution: allow in dependabot.yml (HIGH)."""
        r = self._rule("dependabot_insecure_exec")
        if not r:
            return
        pattern = re.compile(r"insecure-external-code-execution\s*:\s*allow")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="dependabot_insecure_exec"
                )
                return

    def _check_gha_github_app_no_revoke(self, file_path, lines):
        """Detect skip-token-revoke: true in create-github-app-token (HIGH)."""
        r = self._rule("gha_github_app_no_revoke")
        if not r:
            return
        pattern = re.compile(r"skip-token-revoke\s*:\s*true")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="gha_github_app_no_revoke"
                )
                return

    def _check_gha_confused_deputy(self, file_path, content, lines):
        """Detect auto-merges gated on github.actor == bot (HIGH)."""
        r = self._rule("gha_confused_deputy")
        if not r:
            return
        merge_terms = re.compile(r"(?:auto.?merge|gh pr merge|merge --auto|enable-auto-merge)", re.IGNORECASE)
        if not merge_terms.search(content):
            return
        actor_pattern = re.compile(r"github\.actor\s*==\s*['\"][^'\"]*\[bot\]['\"]")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if actor_pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=85, rule_key="gha_confused_deputy"
                )
                return

    def _check_gha_job_all_secrets(self, file_path, lines):
        """Detect toJSON(secrets) exposing all secrets (HIGH)."""
        r = self._rule("gha_job_all_secrets")
        if not r:
            return
        pattern = re.compile(r"toJSON\s*\(\s*secrets\s*\)")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gha_job_all_secrets"
                )
                return

    def _check_ci_netcat_reverse_shell(self, file_path, lines):
        """Detect nc/netcat with an IP address — potential reverse shell (HIGH)."""
        r = self._rule("ci_netcat_reverse_shell")
        if not r:
            return
        pattern = re.compile(r"(?:\bnc\b|\bnetcat\b)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="ci_netcat_reverse_shell"
                )
                return

    def _check_gha_secrets_bypass_redaction(self, file_path, lines):
        """Detect fromJSON/toJSON(secrets) bypassing log redaction (MEDIUM)."""
        r = self._rule("gha_secrets_bypass_redaction")
        if not r:
            return
        pattern = re.compile(r"(?:fromJSON|toJSON)\s*\(\s*secrets")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gha_secrets_bypass_redaction"
                )
                return

    def _check_gha_actor_check_bypass(self, file_path, lines):
        """Detect security conditions gated on github.actor (MEDIUM)."""
        r = self._rule("gha_actor_check_bypass")
        if not r:
            return
        pattern = re.compile(r"if:.*github\.actor\s*==")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=75, rule_key="gha_actor_check_bypass"
                )
                return

    def _check_ci_debug_trace_enabled(self, file_path, lines):
        """Detect ACTIONS_RUNNER_DEBUG/CI_DEBUG_TRACE: true (MEDIUM)."""
        r = self._rule("ci_debug_trace_enabled")
        if not r:
            return
        pattern = re.compile(
            r"(?:ACTIONS_RUNNER_DEBUG|ACTIONS_STEP_DEBUG|CI_DEBUG_TRACE|system\.debug)\s*:\s*(?:true|['\"]true['\"])",
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="ci_debug_trace_enabled"
                )
                return

    def _check_gha_secrets_without_environment(self, file_path, content):
        """Detect non-GITHUB_TOKEN secrets on risky triggers without environment: (MEDIUM)."""
        r = self._rule("gha_secrets_without_environment")
        if not r:
            return
        risky_triggers = re.compile(r"(?:pull_request_target|issue_comment|workflow_run)")
        if not risky_triggers.search(content):
            return
        secrets_pattern = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)")
        if not secrets_pattern.search(content):
            return
        if "environment:" in content:
            return
        self._add_finding(
            "CICD", r["name"], file_path, 1, "# (secrets on risky trigger without environment:)",
            "MEDIUM", r["risk"], r["solution"], r["benefit"],
            confidence=70, rule_key="gha_secrets_without_environment"
        )

    def _check_gha_unsound_condition(self, file_path, lines):
        """Detect if: written as a YAML scalar block (| or >) — always-true condition (MEDIUM)."""
        r = self._rule("gha_unsound_condition")
        if not r:
            return
        pattern = re.compile(r"if:\s*[|>]\s*$")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gha_unsound_condition"
                )
                return

    def _check_gha_workflow_dispatch_inputs(self, file_path, content, lines):
        """Detect workflow_dispatch with defined inputs (LOW)."""
        r = self._rule("gha_workflow_dispatch_inputs")
        if not r:
            return
        if "workflow_dispatch" not in content or "inputs:" not in content:
            return
        in_dispatch = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "workflow_dispatch" in stripped:
                in_dispatch = True
            if in_dispatch and "inputs:" in stripped:
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "LOW", r["risk"], r["solution"], r["benefit"],
                    confidence=80, rule_key="gha_workflow_dispatch_inputs"
                )
                return

    def _check_gha_version_comment_missing(self, file_path, lines):
        """Detect action SHAs without a version comment (LOW)."""
        r = self._rule("gha_version_comment_missing")
        if not r:
            return
        sha_pattern = re.compile(r"uses:\s*\S+@([0-9a-f]{40})")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = sha_pattern.search(stripped)
            if match and "#" not in stripped:
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "LOW", r["risk"], r["solution"], r["benefit"],
                    confidence=85, rule_key="gha_version_comment_missing"
                )
                return

    def _check_gha_local_action(self, file_path, lines):
        """Detect usage of local actions (uses: ./) (LOW)."""
        r = self._rule("gha_local_action")
        if not r:
            return
        pattern = re.compile(r"uses:\s*\./")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "LOW", r["risk"], r["solution"], r["benefit"],
                    confidence=85, rule_key="gha_local_action"
                )
                return

    def _check_gitlab_double_pipeline(self, file_path, lines):
        """Detect duplicated GitLab CI pipeline rules on merge_request_event (LOW)."""
        r = self._rule("gitlab_double_pipeline")
        if not r:
            return
        pattern = re.compile(r"\$CI_PIPELINE_SOURCE\s*==\s*[\"']merge_request_event[\"']")
        matches = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                matches.append((i, stripped))
        if len(matches) >= 2:
            i, code = matches[0]
            self._add_finding(
                "CICD", r["name"], file_path, i + 1, code,
                "LOW", r["risk"], r["solution"], r["benefit"],
                confidence=80, rule_key="gitlab_double_pipeline"
            )

    def _check_gha_credentials_on_disk(self, file_path, lines):
        """Detect persist-credentials: true in actions/checkout (MEDIUM)."""
        r = self._rule("gha_credentials_on_disk")
        if not r:
            return

        pattern = re.compile(r"persist-credentials\s*:\s*true")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=95, rule_key="gha_credentials_on_disk"
                )
                return

    def _check_gha_github_env_write(self, file_path, lines):
        """Detect untrusted event data written into $GITHUB_ENV (HIGH)."""
        r = self._rule("gha_github_env_write")
        if not r:
            return

        pattern = re.compile(
            r"\$\{\{[^}]*github\.event\.[^}]*\}\}[^#\n]*>>\s*\$GITHUB_ENV"
        )
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="gha_github_env_write"
                )
                return

    def _check_ci_docker_privileged(self, file_path, lines):
        """Detect privileged Docker containers in CI/CD pipelines (HIGH)."""
        r = self._rule("ci_docker_privileged")
        if not r:
            return

        pattern = re.compile(r"(?:--privileged\b|privileged:\s*true)")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "HIGH", r["risk"], r["solution"], r["benefit"],
                    confidence=90, rule_key="ci_docker_privileged"
                )
                return

    def _check_gha_dangerous_artefact(self, file_path, content, lines):
        """Detect artifact uploads containing sensitive files (MEDIUM)."""
        r = self._rule("gha_dangerous_artefact")
        if not r:
            return

        upload_pattern = re.compile(r"(?:upload-artifact|artifacts\s*:)", re.IGNORECASE)
        sensitive_pattern = re.compile(
            r"(?:\.env\b|\.key\b|\.pem\b|\.pfx\b|\.p12\b|id_rsa\b|id_ed25519\b|\.credentials\b|secrets?/|private[_-]?key)",
            re.IGNORECASE
        )

        if not upload_pattern.search(content) or not sensitive_pattern.search(content):
            return

        in_upload_block = False
        upload_line = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if upload_pattern.search(stripped):
                in_upload_block = True
                upload_line = i
            if in_upload_block and sensitive_pattern.search(stripped):
                self._add_finding(
                    "CICD", r["name"], file_path, i + 1, stripped,
                    "MEDIUM", r["risk"], r["solution"], r["benefit"],
                    confidence=80, rule_key="gha_dangerous_artefact"
                )
                return

    def _check_workflow_not_in_codeowners(self, file_path):
        """Detect missing .github/workflows/ entry in CODEOWNERS (LOW)."""
        r = self._rule("workflow_not_in_codeowners")
        if not r:
            return

        # Only check once (first workflow file detected)
        if hasattr(self, "_codeowners_checked"):
            return
        self._codeowners_checked = True

        # Look for CODEOWNERS
        project_path = self.root_dir
        codeowners_paths = [
            os.path.join(project_path, "CODEOWNERS"),
            os.path.join(project_path, ".github", "CODEOWNERS"),
            os.path.join(project_path, "docs", "CODEOWNERS"),
        ]

        codeowners_content = None
        for cp in codeowners_paths:
            if os.path.isfile(cp):
                codeowners_content = self._read_file(cp)
                break

        if codeowners_content is None:
            # No CODEOWNERS at all — don't raise a finding
            return

        if ".github/workflows" not in codeowners_content:
            self._add_finding(
                "CICD", r["name"], file_path, 1,
                "CODEOWNERS missing .github/workflows/",
                "LOW", r["risk"], r["solution"], r["benefit"],
                confidence=65, rule_key="workflow_not_in_codeowners"
            )
