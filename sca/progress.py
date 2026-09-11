"""
Reporter — point d'entrée unique pour la sortie utilisateur de l'audit.

Trois cibles indépendantes routées par seuil :
  - console (stdout/stderr) : seuil contrôlé par --quiet (vs normal)
  - log_file (--with-logs)  : capture verbeuse avec timestamps [HH:MM:SS]
  - debug (sca.debug)       : cohabite — chaque message émis devient aussi
                              un logger.log() vers le logger 'sca.progress'

Le code appelant ignore les cibles : il appelle phase(), info(), detail(),
warn(), error(), result(), step(), lang_scan(), category_done(),
taint_pass1(), taint_flows(). Le routeur _emit() décide pour chaque cible.

Niveaux intrinsèques (du moins urgent au plus urgent) :
  TRACE  : ultra-verbeux, dump complet (debug=trace uniquement)
  DETAIL : interne (fichier log et debug=detail)
  INFO   : info utilisateur courante
  PROGRESS : étape numérotée [n/N]
  WARN   : avertissement (tier ne supporte pas SARIF, pip-audit absent…)
  ERROR  : erreur — TOUJOURS visible, même en quiet (sur stderr)
  RESULT : résultat final (chemin rapport, score) — visible aussi en quiet

Matrice de routing :
                    │ console=normal │ console=quiet │ log_file │ debug
  ──────────────────┼────────────────┼───────────────┼──────────┼──────
  RESULT (toujours) │       ✓        │       ✓       │    ✓     │  ✓
  ERROR             │   ✓ (stderr)   │   ✓ (stderr)  │    ✓     │  ✓
  WARN              │       ✓        │       ✗       │    ✓     │  ✓
  PROGRESS          │       ✓        │       ✗       │    ✓     │  ✓
  INFO              │       ✓        │       ✗       │    ✓     │  ✓
  DETAIL            │       ✗        │       ✗       │    ✓     │  ✓ (>=detail)
  TRACE             │       ✗        │       ✗       │    ✗     │  ✓ (=trace)
"""

import sys
import logging
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Optional, Callable, TextIO


class Level(IntEnum):
    """Intrinsic severity level of a message, invisible to the calling code."""
    TRACE    = 10
    DETAIL   = 20
    INFO     = 30
    PROGRESS = 40
    WARN     = 50
    ERROR    = 60
    RESULT   = 70


# Reporter → Python logging level mapping (cohabits with sca/debug.py)
# DETAIL=15 and TRACE=5 are the custom levels registered by sca.debug.
_LOGGING_LEVEL = {
    Level.TRACE:    5,
    Level.DETAIL:   15,
    Level.INFO:     logging.INFO,
    Level.PROGRESS: logging.INFO,
    Level.WARN:     logging.WARNING,
    Level.ERROR:    logging.ERROR,
    Level.RESULT:   logging.INFO,
}


def _identity(key: str) -> str:
    """Return the key unchanged; fallback i18n when no translator is supplied."""
    return key


class Reporter:
    """Single entry point for audit output (console + log file + debug)."""

    def __init__(self, *, t_console: Optional[Callable[[str], str]] = None,
                 quiet: bool = False,
                 log_file_path: Optional[str] = None,
                 stdout: Optional[TextIO] = None,
                 stderr: Optional[TextIO] = None):
        """Initialize routing thresholds and open the log file if requested."""
        self._t = t_console or _identity
        # Override stdout/stderr (tests). Otherwise: lazy resolution of sys.stdout
        # on each emission, to follow redirections made downstream.
        self._stdout_override = stdout
        self._stderr_override = stderr

        # Console threshold: quiet => only ERROR and RESULT pass through (RESULT > ERROR
        # numerically, so threshold=ERROR lets both through).
        self._console_threshold = Level.ERROR if quiet else Level.INFO
        self._quiet = quiet

        # Log file target (--with-logs)
        self._log_fh: Optional[TextIO] = None
        self._log_path: Optional[str] = log_file_path
        self._log_threshold: Optional[Level] = None
        if log_file_path:
            Path(log_file_path).parent.mkdir(parents=True, exist_ok=True)
            self._log_fh = open(log_file_path, "w", encoding="utf-8")
            self._log_threshold = Level.DETAIL  # verbose capture

        # Debug target (cohabits with sca/debug.py via the 'sca' namespace)
        self._logger = logging.getLogger("sca.progress")

        # [n/N] phase counter
        self._phase_total = 0
        self._phase_index = 0

    # =========================================================================
    # CONFIGURATION
    # =========================================================================
    def init_phases(self, total: int) -> None:
        """Set the total phase count used for [n/N] numbering."""
        self._phase_total = max(0, total)
        self._phase_index = 0

    @property
    def log_path(self) -> Optional[str]:
        """Return the log file path, or None if logging to file is disabled."""
        return self._log_path

    @property
    def quiet(self) -> bool:
        """Return whether quiet mode (console limited to ERROR/RESULT) is active."""
        return self._quiet

    @property
    def with_logs(self) -> bool:
        """Return whether a log file target is currently open."""
        return self._log_fh is not None

    def close(self) -> None:
        """Close the log file if open. Idempotent."""
        if self._log_fh:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            finally:
                self._log_fh = None

    # =========================================================================
    # LOW-LEVEL ROUTING
    # =========================================================================
    def _emit(self, level: Level, msg: str) -> None:
        """Route a message to the 3 targets (console/log file/debug) per their thresholds."""
        # 1. Console — lazy resolution of sys.stdout/stderr (tests can
        # patch sys.stdout after the Reporter is instantiated).
        if level >= self._console_threshold:
            if level == Level.ERROR:
                stream = self._stderr_override if self._stderr_override is not None else sys.stderr
            else:
                stream = self._stdout_override if self._stdout_override is not None else sys.stdout
            print(msg, file=stream, flush=True)
        # 2. Log file ([HH:MM:SS] prefix)
        if self._log_fh is not None and self._log_threshold is not None \
                and level >= self._log_threshold:
            ts = datetime.now().strftime("[%H:%M:%S]")
            for line in msg.splitlines() or [""]:
                self._log_fh.write(f"{ts} {line}\n")
            self._log_fh.flush()
        # 3. Debug (let Python logging handle its own handlers)
        self._logger.log(_LOGGING_LEVEL[level], msg)

    # =========================================================================
    # BUSINESS API — each method knows its own intrinsic level
    # =========================================================================

    def banner(self, line: str) -> None:
        """Emit a banner line (title, separator) at INFO level."""
        self._emit(Level.INFO, line)

    def phase(self, key: str, icon: str = "→") -> None:
        """Emit a numbered phase [n/N]; `key` is translated via `phase_{key}`."""
        self._phase_index += 1
        prefix = f"[{self._phase_index}/{self._phase_total}] " if self._phase_total else ""
        label = self._t(f"phase_{key}")
        # If the translation doesn't exist, _t returns the key: fall back to displaying key
        if label == f"phase_{key}":
            label = key
        self._emit(Level.PROGRESS, f"{prefix}{icon} {label}...")

    def rules_loaded(self, builtin: int, custom: int, total: int, langs: str = "") -> None:
        """Report rule counts (builtin/custom/total) and, optionally, active languages."""
        msg = self._t("progress_rules_loaded_detail").format(
            builtin=builtin, custom=custom, total=total
        )
        self._emit(Level.INFO, f"   {msg}")
        if langs:
            langs_msg = self._t("progress_active_languages").format(langs=langs)
            self._emit(Level.INFO, f"   → {langs_msg}")

    def phase_custom(self, label: str, icon: str = "→") -> None:
        """Emit a numbered phase [n/N] using a direct label (no i18n key)."""
        self._phase_index += 1
        prefix = f"[{self._phase_index}/{self._phase_total}] " if self._phase_total else ""
        self._emit(Level.PROGRESS, f"{prefix}{icon} {label}...")

    def lang_scan(self, lang: str, count: int, duration: float = 0.0) -> None:
        """Report the number of files scanned for a language and how long it took."""
        msg = self._t("progress_lang_scan").format(
            lang=lang.title(), count=count, duration=duration
        )
        self._emit(Level.INFO, f"   📂 {msg}")

    def category_done(self, category: str, rules: int, files: int,
                       findings: int, duration: float) -> None:
        """Report completion of a rule category with rule/file/finding counts and duration."""
        msg = self._t("progress_category_done").format(
            category=category, rules=rules, files=files,
            findings=findings, duration=duration
        )
        self._emit(Level.INFO, f"   → {msg}")

    def taint_pass1(self, language: str, count: int) -> None:
        """Report taint analysis pass 1 (function extraction) results for a language."""
        msg = self._t("progress_taint_pass1").format(language=language, count=count)
        self._emit(Level.INFO, f"      🧠 → {msg}")

    def taint_pass2(self, language: str) -> None:
        """Report the start of taint analysis pass 2 (inter-procedural propagation)."""
        msg = self._t("progress_taint_pass2").format(language=language.title())
        self._emit(Level.INFO, f"      → {msg}")

    def taint_flows(self, language: str, count: int) -> None:
        """Report the number of tainted data flows detected for a language."""
        msg = self._t("progress_taint_flows").format(language=language, count=count)
        self._emit(Level.INFO, f"      → {msg}")

    def step(self, msg: str, icon: str = "") -> None:
        """Emit a secondary step message (pip-audit, npm audit, baseline...)."""
        prefix = f"   {icon} " if icon else "   "
        self._emit(Level.INFO, f"{prefix}{msg}")

    def info(self, msg: str) -> None:
        """Emit a user-facing informational message (INFO level)."""
        self._emit(Level.INFO, msg)

    def detail(self, msg: str) -> None:
        """Emit a detail message (log file only, never console)."""
        self._emit(Level.DETAIL, msg)

    def trace(self, msg: str) -> None:
        """Emit a trace message (debug only, never console nor log file)."""
        self._emit(Level.TRACE, msg)

    def warn(self, msg: str) -> None:
        """Emit a warning, visible on normal console but not in quiet mode."""
        self._emit(Level.WARN, f"⚠️  {msg}")

    def error(self, msg: str) -> None:
        """Emit an error — ALWAYS visible (stderr), even in quiet mode."""
        self._emit(Level.ERROR, f"❌ {msg}")

    def result(self, msg: str) -> None:
        """Emit the final result — always visible (report path, score)."""
        self._emit(Level.RESULT, msg)
