"""
Mixin base de données — audit du schéma PostgreSQL et détection de changements.
"""
import os
import re
import sys
import json
import logging
import subprocess
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple

from sca import SCRIPT_DIR

logger = logging.getLogger("sca.database")


class AuditDatabaseMixin:
    """PostgreSQL schema audit methods."""

    # =========================================================================
    # AUDIT DATABASE (PostgreSQL Schema)
    # =========================================================================
    def _audit_database(self):
        """Audit PostgreSQL schema changes."""
        # The [n/N] numbering and the icon are emitted by
        # AuditRunner._run_phase via self.reporter.phase("database").

        db_config = self.config.get("database", {})
        if not db_config.get("enabled"):
            return

        # 1. Load the credentials from the project's .env file
        credentials = self._load_db_credentials(db_config)
        if credentials:
            logger.detail(self.t_console("log_db_credentials").format(
                user=credentials["user"], host=credentials["host"],
                port=credentials["port"], db=credentials["database"]))
        if not credentials:
            r = self._rule("db_config_missing")
            self._add_finding(
                "DATABASE", r["name"], "audit.config.json", 0,
                "Impossible de lire les credentials depuis .env",
                "MEDIUM", r["risk"], r["solution"], r["benefit"]
            , rule_key="db_config_missing")
            return

        # 2. Extract the current schema
        current_schema = self._extract_pg_schema(credentials)
        if current_schema is None:
            return  # Error already reported

        # Store the schema for export into SCA-DATA
        self.database_schema = current_schema

        # 3. Load the baseline from the latest SCA-DATA (no separate file)
        baseline = self._load_schema_from_history()
        logger.detail(self.t_console("log_baseline_schema").format(status="found" if baseline else "absent"))

        # 4. Compare and generate findings
        changes = []
        if baseline:
            changes = self._compare_schemas(baseline, current_schema, db_config)

            # 5. Analyze code usages if enabled
            if db_config.get("code_analysis", {}).get("enabled", True):
                self._analyze_code_usage(changes, db_config)

            # Add a finding for each change
            for change in changes:
                self._add_finding(
                    "DATABASE",
                    change["rule"],
                    f"table:{change['table']}" + (f".{change.get('column', '')}" if change.get('column') else ""),
                    0,
                    change["description"],
                    change["severity"],
                    change["risk"],
                    change["solution"],
                    "Schéma database stable et cohérent avec le code."
                )
        else:
            self.reporter.step(self.t_console('database_first_run'), icon="📋")

        # 6. Compute schema statistics
        self.database_stats = self._calculate_schema_stats(current_schema, baseline, changes)

    def _load_db_credentials(self, db_config: dict) -> Optional[dict]:
        """Load credentials from audit.config.json plus the password from .env."""
        # 1. Read host/port/database/user directly from the JSON config
        credentials = {
            "host": db_config.get("host", "localhost"),
            "port": db_config.get("port", "5432"),
            "database": db_config.get("database", ""),
            "user": db_config.get("user", ""),
            "password": "",
        }

        # 2. Check that the essential fields are filled in
        if not credentials["database"] or not credentials["user"]:
            # Interactive mode: prompt for the missing info
            if sys.stdin.isatty():
                credentials = self._interactive_db_setup(db_config, credentials)
                if not credentials:
                    return None
            else:
                self.reporter.warn(self.t_console('credentials_incomplete'))
                return None

        # 3. Read the password from the .env file
        env_file = db_config.get("password_env_file", ".env")
        if not os.path.isabs(env_file):
            env_file = os.path.join(self.root_dir, env_file)
        env_var = db_config.get("password_env_var", "DB_PASSWORD")

        if os.path.exists(env_file):
            try:
                with open(env_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            if key.strip() == env_var:
                                credentials["password"] = value.strip().strip('"\'')
                                break
            except IOError as e:
                self.reporter.warn(f"{self.t_console('env_read_error')}: {e}")
                return None
        else:
            self.reporter.warn(f"{self.t_console('env_not_found')}: {env_file}")
            return None

        if not credentials["password"]:
            self.reporter.warn(f"{self.t_console('password_not_found')}: {env_var} in {env_file}")
            return None

        self.reporter.step(f"{self.t_console('credentials')}: {credentials['user']}@{credentials['host']}:{credentials['port']}/{credentials['database']}", icon="✅")
        return credentials

    def _interactive_db_setup(self, db_config: dict, credentials: dict) -> Optional[dict]:
        """Interactively prompt for connection info and write it to the config."""
        self.reporter.info(f"\n   🗄️  {self.t_console('db_config_required')}")
        self.reporter.info(f"   {'─' * 40}")

        # Prompt for each field with the current value as the default
        fields = [
            ("host", "Host", credentials.get("host", "localhost")),
            ("port", "Port", credentials.get("port", "5432")),
            ("database", "Database name", credentials.get("database", "")),
            ("user", "User", credentials.get("user", "")),
        ]
        for key, label, default in fields:
            prompt = f"   {label}"
            if default:
                prompt += f" [{default}]"
            prompt += ": "
            value = input(prompt).strip()
            credentials[key] = value if value else default

        # Check that the required fields are filled in
        if not credentials["database"] or not credentials["user"]:
            self.reporter.warn(self.t_console('credentials_incomplete'))
            return None

        # Prompt for the .env path and the password variable name
        env_file = db_config.get("password_env_file", ".env")
        env_var = db_config.get("password_env_var", "DB_PASSWORD")

        value = input(f"   Password .env file [{env_file}]: ").strip()
        if value:
            env_file = value
        value = input(f"   Password variable name [{env_var}]: ").strip()
        if value:
            env_var = value

        # Prompt for the password
        import getpass
        password = getpass.getpass(f"   Password (hidden): ")
        if not password:
            self.reporter.warn(self.t_console('credentials_incomplete'))
            return None
        credentials["password"] = password

        # Write the password to the .env file
        env_path = env_file if os.path.isabs(env_file) else os.path.join(self.root_dir, env_file)
        self._write_password_to_env(env_path, env_var, password)

        # Update audit.config.json with the new values
        config_path = os.path.join(self.root_dir, "audit.config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                db_section = config.setdefault("database", {})
                db_section["enabled"] = True
                db_section["host"] = credentials["host"]
                db_section["port"] = credentials["port"]
                db_section["database"] = credentials["database"]
                db_section["user"] = credentials["user"]
                db_section["password_env_file"] = env_file
                db_section["password_env_var"] = env_var
                # Remove old, obsolete keys
                db_section.pop("env_file", None)
                db_section.pop("env_vars", None)
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                    f.write('\n')
                self.reporter.step(self.t_console('db_config_saved').format(path=config_path), icon="✅")
            except (IOError, json.JSONDecodeError) as e:
                self.reporter.warn(self.t_console('db_config_save_error').format(error=e))

        return credentials

    def _write_password_to_env(self, env_path: str, env_var: str, password: str):
        """Write or update the password in the .env file."""
        lines = []
        found = False
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip() and not line.strip().startswith('#') and '=' in line:
                    key = line.split('=', 1)[0].strip()
                    if key == env_var:
                        lines[i] = f'{env_var}="{password}"\n'
                        found = True
                        break
        if not found:
            lines.append(f'{env_var}="{password}"\n')
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        self.reporter.step(self.t_console('db_password_written').format(path=env_path, var=env_var), icon="✅")

    def _extract_pg_schema(self, credentials: dict) -> Optional[dict]:
        """Extract the PostgreSQL schema via psycopg2 or psql."""
        try:
            import psycopg2
            return self._extract_schema_psycopg2(credentials)
        except ImportError:
            # Check whether psql is available
            import shutil
            psql_available = shutil.which('psql') is not None

            if psql_available:
                self.reporter.info(f"   ℹ️  {self.t_console('psycopg2_fallback')}")
                self.reporter.step(f"{self.t_console('psycopg2_install_hint')}: pip install psycopg2-binary")
                return self._extract_schema_psql(credentials)
            else:
                self.reporter.error(self.t_console('no_pg_tool'))
                self.reporter.info(f"   {self.t_console('no_pg_tool_detail')}: psycopg2, psql")
                self.reporter.info(f"   {self.t_console('db_install_hint')}")
                self.reporter.info("     pip install psycopg2-binary")
                self.reporter.info("     brew install libpq && brew link libpq    (macOS)")
                self.reporter.info("     sudo apt install postgresql-client       (Debian/Ubuntu)")
                self.reporter.info("     sudo dnf install postgresql              (Fedora/RHEL)")
                r = self._rule("db_tool_missing")
                self._add_finding(
                    "DATABASE", r["name"], "audit.config.json", 0,
                    "Impossible d'extraire le schéma PostgreSQL : ni psycopg2 ni psql disponible",
                    "HIGH", r["risk"], r["solution"], r["benefit"]
                , rule_key="db_tool_missing")
                return None

    def _extract_schema_psycopg2(self, credentials: dict) -> Optional[dict]:
        """Extract the schema via psycopg2."""
        import psycopg2

        schema = {
            "timestamp": datetime.now().isoformat(),
            "database": credentials["database"],
            "tables": {},
            "enums": {}
        }

        try:
            conn = psycopg2.connect(
                host=credentials["host"],
                port=int(credentials["port"]),
                database=credentials["database"],
                user=credentials["user"],
                password=credentials["password"]
            )
            cur = conn.cursor()

            # Retrieve the tables
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """)
            tables = [row[0] for row in cur.fetchall()]

            for table_name in tables:
                schema["tables"][table_name] = {
                    "columns": {},
                    "constraints": {},
                    "indexes": []
                }

                # Columns
                cur.execute("""
                    SELECT column_name, data_type, is_nullable, column_default,
                           character_maximum_length, numeric_precision
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = %s
                    ORDER BY ordinal_position
                """, (table_name,))

                for col in cur.fetchall():
                    col_type = col[1]
                    if col[4]:  # character_maximum_length
                        col_type = f"{col[1]}({col[4]})"
                    elif col[5]:  # numeric_precision
                        col_type = f"{col[1]}({col[5]})"

                    schema["tables"][table_name]["columns"][col[0]] = {
                        "type": col_type,
                        "nullable": col[2] == "YES",
                        "default": col[3]
                    }

                # Constraints
                cur.execute("""
                    SELECT tc.constraint_name, tc.constraint_type,
                           string_agg(kcu.column_name, ', ' ORDER BY kcu.ordinal_position)
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                        ON tc.constraint_name = kcu.constraint_name
                        AND tc.table_schema = kcu.table_schema
                    WHERE tc.table_schema = 'public' AND tc.table_name = %s
                    GROUP BY tc.constraint_name, tc.constraint_type
                """, (table_name,))

                for constraint in cur.fetchall():
                    schema["tables"][table_name]["constraints"][constraint[0]] = {
                        "type": constraint[1],
                        "columns": constraint[2].split(", ") if constraint[2] else []
                    }

                # Indexes
                cur.execute("""
                    SELECT indexname
                    FROM pg_indexes
                    WHERE schemaname = 'public' AND tablename = %s
                """, (table_name,))
                schema["tables"][table_name]["indexes"] = [row[0] for row in cur.fetchall()]

            # Enums
            cur.execute("""
                SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder)
                FROM pg_type t
                JOIN pg_enum e ON t.oid = e.enumtypid
                JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname = 'public'
                GROUP BY t.typname
            """)
            for enum in cur.fetchall():
                schema["enums"][enum[0]] = list(enum[1])

            cur.close()
            conn.close()

            self.reporter.step(f"{self.t_console('schema_extracted')}: {len(tables)} {self.t_console('tables')}, {len(schema['enums'])} {self.t_console('enums')}", icon="✅")
            return schema

        except Exception as e:
            r = self._rule("db_connection_error")
            self._add_finding(
                "DATABASE", r["name"], "PostgreSQL", 0,
                str(e), "HIGH", r["risk"], r["solution"], r["benefit"], rule_key="db_connection_error"
            )
            return None

    def _extract_schema_psql(self, credentials: dict) -> Optional[dict]:
        """Extract the schema via psql (fallback when psycopg2 is unavailable)."""
        schema = {
            "timestamp": datetime.now().isoformat(),
            "database": credentials["database"],
            "tables": {},
            "enums": {}
        }

        env = os.environ.copy()
        env["PGPASSWORD"] = credentials["password"]

        def run_psql(query: str) -> Optional[str]:
            """Run a query via the psql CLI and return its stdout, or None on failure."""
            try:
                result = subprocess.run(
                    ["psql", "-h", credentials["host"], "-p", str(credentials["port"]),
                     "-U", credentials["user"], "-d", credentials["database"],
                     "-t", "-A", "-c", query],
                    capture_output=True, text=True, env=env, timeout=30
                )
                if result.returncode != 0:
                    return None
                return result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return None

        # Retrieve the tables
        tables_output = run_psql(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name"
        )
        if tables_output is None:
            r = self._rule("db_psql_error")
            self._add_finding(
                "DATABASE", r["name"], "PostgreSQL", 0,
                "Impossible d'exécuter psql", "HIGH", r["risk"], r["solution"], r["benefit"]
            , rule_key="db_psql_error")
            return None

        tables = [t for t in tables_output.split('\n') if t]

        for table_name in tables:
            schema["tables"][table_name] = {"columns": {}, "constraints": {}, "indexes": []}

            # Columns (simplified format via psql)
            cols_output = run_psql(
                f"SELECT column_name, data_type, is_nullable, column_default "
                f"FROM information_schema.columns WHERE table_schema = 'public' "
                f"AND table_name = '{table_name}' ORDER BY ordinal_position"
            )
            if cols_output:
                for line in cols_output.split('\n'):
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            schema["tables"][table_name]["columns"][parts[0]] = {
                                "type": parts[1],
                                "nullable": parts[2] == "YES",
                                "default": parts[3] if len(parts) > 3 else None
                            }

        self.reporter.step(f"{self.t_console('schema_extracted_psql')}: {len(tables)} {self.t_console('tables')}", icon="✅")
        return schema

    def _list_data_files(self) -> List[str]:
        """List DATA files in the history directory.

        Includes files with the current prefix (brand.prefix) AND the
        legacy 'AUDIT-DATA-' prefix for backward compatibility.
        """
        if not os.path.exists(self.datas_dir):
            return []
        current_prefix = f"{self.brand_prefix}-DATA-"
        legacy_prefix = "AUDIT-DATA-"
        return [
            f for f in os.listdir(self.datas_dir)
            if (f.startswith(current_prefix) or f.startswith(legacy_prefix)) and f.endswith(".json")
        ]

    def _load_schema_from_history(self) -> Optional[dict]:
        """Load the schema from the most recent DATA file."""
        json_files = self._list_data_files()
        if not json_files:
            return None

        # Sort by date (most recent last)
        json_files.sort()
        latest_file = os.path.join(self.datas_dir, json_files[-1])

        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                db_data = data.get("database") or {}
                schema = db_data.get("schema")
                if schema:
                    self.reporter.step(f"{self.t_console('baseline_loaded')}: {json_files[-1]}", icon="📂")
                    return schema
        except (json.JSONDecodeError, IOError) as e:
            self.reporter.warn(f"{self.t_console('baseline_read_error')}: {e}")

        return None

    def _calculate_schema_stats(self, current: dict, baseline: Optional[dict], changes: List[dict]) -> dict:
        """Compute schema statistics."""
        tables = current.get("tables", {})
        stats = {
            "tables_count": len(tables),
            "columns_count": sum(len(t.get("columns", {})) for t in tables.values()),
            "indexes_count": sum(len(t.get("indexes", [])) for t in tables.values()),
            "constraints_count": sum(len(t.get("constraints", {})) for t in tables.values()),
            "enums_count": len(current.get("enums", {})),
            "changes": {
                "added": {"tables": 0, "columns": 0, "indexes": 0},
                "dropped": {"tables": 0, "columns": 0, "indexes": 0},
                "modified": {"columns": 0, "types": 0}
            }
        }

        # Count the changes by type
        for change in changes:
            change_type = change.get("type", "")
            if change_type == "table_added":
                stats["changes"]["added"]["tables"] += 1
            elif change_type == "table_dropped":
                stats["changes"]["dropped"]["tables"] += 1
            elif change_type == "column_added":
                stats["changes"]["added"]["columns"] += 1
            elif change_type == "column_dropped":
                stats["changes"]["dropped"]["columns"] += 1
            elif change_type == "index_added":
                stats["changes"]["added"]["indexes"] += 1
            elif change_type == "index_dropped":
                stats["changes"]["dropped"]["indexes"] += 1
            elif change_type in ("type_changed", "nullable_changed"):
                stats["changes"]["modified"]["columns"] += 1

        return stats

    def _compare_schemas(self, baseline: dict, current: dict, db_config: dict) -> List[dict]:
        """Compare two schemas and return the list of changes."""
        changes = []
        severity_config = db_config.get("severity", {})
        track_config = db_config.get("track", {})

        baseline_tables = set(baseline.get("tables", {}).keys())
        current_tables = set(current.get("tables", {}).keys())

        # Added tables
        if track_config.get("tables", True):
            for table in current_tables - baseline_tables:
                changes.append({
                    "type": "table_added",
                    "table": table,
                    "rule": "TABLE_ADDED",
                    "description": f"Nouvelle table: {table}",
                    "severity": severity_config.get("table_added", "INFO"),
                    "risk": "Nouvelle table ajoutée au schéma.",
                    "solution": "Aucune action requise si intentionnel."
                })

        # Dropped tables
        if track_config.get("tables", True):
            for table in baseline_tables - current_tables:
                changes.append({
                    "type": "table_dropped",
                    "table": table,
                    "rule": "TABLE_DROPPED",
                    "description": f"Table supprimée: {table}",
                    "severity": severity_config.get("table_dropped", "HIGH"),
                    "risk": "La suppression d'une table peut causer des erreurs si le code y fait référence.",
                    "solution": "Vérifier que le code ne référence plus cette table."
                })

        # Compare the columns of the common tables
        if track_config.get("columns", True):
            for table in baseline_tables & current_tables:
                baseline_cols = set(baseline["tables"][table].get("columns", {}).keys())
                current_cols = set(current["tables"][table].get("columns", {}).keys())

                # Added columns
                for col in current_cols - baseline_cols:
                    changes.append({
                        "type": "column_added",
                        "table": table,
                        "column": col,
                        "rule": "COLUMN_ADDED",
                        "description": f"Nouvelle colonne: {table}.{col}",
                        "severity": severity_config.get("column_added", "LOW"),
                        "risk": "Nouvelle colonne ajoutée.",
                        "solution": "Aucune action requise si intentionnel."
                    })

                # Dropped columns
                for col in baseline_cols - current_cols:
                    changes.append({
                        "type": "column_dropped",
                        "table": table,
                        "column": col,
                        "rule": "COLUMN_DROPPED",
                        "description": f"Colonne supprimée: {table}.{col}",
                        "severity": severity_config.get("column_dropped", "HIGH"),
                        "risk": "La suppression d'une colonne peut causer des erreurs si le code y fait référence.",
                        "solution": "Vérifier que le code ne référence plus cette colonne."
                    })

                # Modified columns (type, nullable)
                for col in baseline_cols & current_cols:
                    old = baseline["tables"][table]["columns"][col]
                    new = current["tables"][table]["columns"][col]

                    if old.get("type") != new.get("type"):
                        changes.append({
                            "type": "type_changed",
                            "table": table,
                            "column": col,
                            "rule": "TYPE_CHANGED",
                            "description": f"Type modifié: {table}.{col} ({old.get('type')} → {new.get('type')})",
                            "severity": severity_config.get("type_changed", "MEDIUM"),
                            "risk": "Le changement de type peut causer des erreurs de conversion.",
                            "solution": "Vérifier la compatibilité avec le code existant."
                        })

                    if old.get("nullable") != new.get("nullable"):
                        changes.append({
                            "type": "nullable_changed",
                            "table": table,
                            "column": col,
                            "rule": "NULLABLE_CHANGED",
                            "description": f"Nullable modifié: {table}.{col} ({old.get('nullable')} → {new.get('nullable')})",
                            "severity": "MEDIUM" if not new.get("nullable") else "LOW",
                            "risk": "Passer nullable=false peut causer des contraintes NOT NULL violations.",
                            "solution": "S'assurer que le code gère correctement les valeurs NULL."
                        })

        # Compare the indexes
        if track_config.get("indexes", True):
            for table in baseline_tables & current_tables:
                baseline_idx = set(baseline["tables"][table].get("indexes", []))
                current_idx = set(current["tables"][table].get("indexes", []))

                for idx in current_idx - baseline_idx:
                    changes.append({
                        "type": "index_added",
                        "table": table,
                        "index": idx,
                        "rule": "INDEX_ADDED",
                        "description": f"Index ajouté: {idx} sur {table}",
                        "severity": severity_config.get("index_added", "INFO"),
                        "risk": "Nouvel index créé.",
                        "solution": "Aucune action requise."
                    })

                for idx in baseline_idx - current_idx:
                    changes.append({
                        "type": "index_dropped",
                        "table": table,
                        "index": idx,
                        "rule": "INDEX_DROPPED",
                        "description": f"Index supprimé: {idx} sur {table}",
                        "severity": "MEDIUM",
                        "risk": "La suppression d'un index peut impacter les performances.",
                        "solution": "Vérifier que l'index n'était pas nécessaire pour les performances."
                    })

        if changes:
            self.reporter.warn(f"{len(changes)} {self.t_console('changes_detected')}")
        else:
            self.reporter.step(self.t_console('no_changes'), icon="✅")

        return changes

    def _analyze_code_usage(self, changes: List[dict], db_config: dict):
        """Scan the code for usages of the modified/dropped schema elements."""
        escalate = db_config.get("code_analysis", {}).get("escalate_severity", True)

        # Filter changes involving drops or modifications
        critical_changes = [c for c in changes if c["type"] in (
            "column_dropped", "table_dropped", "type_changed", "column_renamed"
        )]

        if not critical_changes:
            return

        # Load all the Python and JavaScript code
        all_code = []
        for filepath in self._find_files(self._py_exts, self._py_paths):
            all_code.extend([
                (filepath, line_num, line)
                for line_num, line in self._read_file(filepath)
            ])
        for filepath in self._find_files(self._js_exts, self._js_paths):
            all_code.extend([
                (filepath, line_num, line)
                for line_num, line in self._read_file(filepath)
            ])

        for change in critical_changes:
            element = change.get("column") or change.get("table")
            if not element:
                continue

            # Search patterns
            patterns = [
                rf'\.{element}\b',           # .column_name
                rf'\[[\'"]{element}[\'"]\]', # ["column_name"] or ['column_name']
                rf'\b{element}\b',           # direct reference
            ]

            references = []
            for filepath, line_num, line in all_code:
                for pattern in patterns:
                    if re.search(pattern, line):
                        references.append({
                            "file": filepath,
                            "line": line_num,
                            "code": line.strip()[:100]
                        })
                        break  # Only one reference per line

            if references:
                change["code_references"] = references
                change["description"] += f" (utilisé dans {len(references)} fichier(s))"

                # Escalate the severity if configured
                if escalate:
                    if change["severity"] == "HIGH":
                        change["severity"] = "CRITICAL"
                        change["rule"] += "_WITH_USAGE"
                    elif change["severity"] == "MEDIUM":
                        change["severity"] = "HIGH"
                        change["rule"] += "_WITH_USAGE"

                change["risk"] += f" Trouvé dans: {', '.join(set(r['file'] for r in references[:3]))}"
                if len(references) > 3:
                    change["risk"] += f" et {len(references) - 3} autre(s)..."
