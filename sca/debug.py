"""
Debug logging — multi-level configuration for diagnostics.

Levels:
  info   = INFO (main steps, summaries)
  detail = DETAIL (scanned files, executed rules, matches)
  trace  = TRACE (every line read, every regex)

Usage:
  --debug        → info level (INFO)
  --debug=detail → detail level (DETAIL)
  --debug=trace  → trace level (TRACE)
  --verbose      → alias for --debug (info)
  SCA_DEBUG=detail → environment variable

Log format:
  stderr: [SCA-DBG] LEVEL  module | file:line function() [thread:PID] | message
  file:   datetime  LEVEL  module | file:line function() [thread:PID] | message

Log file: {output_dir}/{prefix}-DEBUG-YYYY-MM-DD-HH-MM.log
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# ============================================================================
# CUSTOM LEVELS
# ============================================================================

TRACE = 5    # every line, every regex, full dump
DETAIL = 15  # scanned files, executed rules, matches

logging.addLevelName(TRACE, "TRACE")
logging.addLevelName(DETAIL, "DETAIL")


def _log_detail(self, message, *args, **kwargs):
    """Log at the DETAIL level (15)."""
    if self.isEnabledFor(DETAIL):
        self._log(DETAIL, message, args, stacklevel=2, **kwargs)


def _log_trace(self, message, *args, **kwargs):
    """Log at the TRACE level (5)."""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, stacklevel=2, **kwargs)


# Add the methods to the Logger class
logging.Logger.detail = _log_detail
logging.Logger.trace = _log_trace

# ============================================================================
# JSON FORMAT (NDJSON for CI/CD)
# ============================================================================

class JsonFormatter(logging.Formatter):
    """Format each LogRecord as a single JSON line (NDJSON)."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a LogRecord to a JSON string, including known extra fields."""
        entry: Dict[str, Any] = {
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }
        # Optional extra fields (added by the helpers)
        for key in ("event", "phase", "duration", "rule", "files", "matches",
                     "findings", "severity", "score", "file", "size_kb"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        return json.dumps(entry, ensure_ascii=False)


# ============================================================================
# PUBLIC FUNCTIONS
# ============================================================================

# Current debug format (text or json)
_debug_format = "text"


def get_debug_format() -> str:
    """Return the current debug output format ('text' or 'json')."""
    return _debug_format


# CLI level (string) → logging level mapping
_LEVEL_MAP = {
    "info": logging.INFO,     # main steps
    "detail": DETAIL,         # files and rules
    "trace": TRACE,           # everything
}


def get_debug_level() -> Optional[str]:
    """Return the debug level from the SCA_DEBUG environment variable.

    Returns:
        Optional[str]: "info", "detail", "trace", or None if unset/invalid.
    """
    val = os.environ.get("SCA_DEBUG", "").lower().strip()
    if val in _LEVEL_MAP:
        return val
    return None


def setup_debug(level: Optional[str], reports_dir: str = None,
                brand_prefix: str = "SCA",
                debug_format: str = "text") -> Optional[str]:
    """Configure the debug logging system.

    Args:
        level: debug level ("info", "detail", "trace", or None for OFF)
        reports_dir: directory for the log file (None = no file)
        brand_prefix: prefix for the log file name
        debug_format: stderr output format ("text" or "json")

    Returns:
        Path of the created log file, or None if level is None.
    """
    global _debug_format
    _debug_format = debug_format

    logger = logging.getLogger("sca")

    # No debug: total silence
    if not level:
        logger.setLevel(logging.WARNING)
        return None

    log_level = _LEVEL_MAP.get(level, logging.INFO)
    logger.setLevel(log_level)

    # Avoid duplicates when called multiple times
    # (1st call = stderr, 2nd call = add file)
    has_stderr = any(
        isinstance(h, logging.StreamHandler) and h.stream == sys.stderr
        for h in logger.handlers
    )

    # Console handler (stderr)
    if not has_stderr:
        if debug_format == "json":
            stderr_fmt = JsonFormatter()
        else:
            stderr_fmt = logging.Formatter(
                "[%(prefix)s-DBG] %(levelname)-7s %(name)-20s | %(filename)s:%(lineno)d %(funcName)s() [%(threadName)s:%(process)d] | %(message)s",
                defaults={"prefix": brand_prefix}
            )
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(log_level)
        stderr_handler.setFormatter(stderr_fmt)
        logger.addHandler(stderr_handler)

    # File handler (if reports_dir provided — always text format)
    log_path = None
    if reports_dir:
        has_file = any(
            isinstance(h, logging.FileHandler) for h in logger.handlers
        )
        if not has_file:
            Path(reports_dir).mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
            log_path = str(
                Path(reports_dir) / f"{brand_prefix}-DEBUG-{timestamp}.log"
            )
            file_fmt = logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)-20s | %(filename)s:%(lineno)d %(funcName)s() [%(threadName)s:%(process)d] | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)

    return log_path


# ============================================================================
# STRUCTURED LOGGING HELPERS
# ============================================================================

def log_phase_start(phase: str):
    """Log the start of an audit phase."""
    _logger = logging.getLogger("sca.runner")
    _logger.info("=> [PHASE] %s START", phase,
                 extra={"event": "phase_start", "phase": phase})


def log_phase_end(phase: str, duration: float, findings: int,
                  detail: str = ""):
    """Log the end of an audit phase with its duration and finding count."""
    _logger = logging.getLogger("sca.runner")
    msg = "<= [PHASE] %s END (%.2fs) — %d findings"
    args = [phase, duration, findings]
    if detail:
        msg += " (%s)"
        args.append(detail)
    _logger.info(msg, *args,
                 extra={"event": "phase_end", "phase": phase,
                         "duration": round(duration, 3), "findings": findings})


def log_scan_stats(category: str, found: int, excluded: int, scanned: int,
                   lines: int = 0):
    """Log file scanning statistics for a category."""
    _logger = logging.getLogger("sca.runner")
    _logger.info("Files: %d found, %d excluded, %d scanned (%d lines)",
                 found, excluded, scanned, lines,
                 extra={"event": "scan_stats", "phase": category,
                         "files": scanned})


def log_rule_result(rule_key: str, files_checked: int, matches: int,
                    findings: int, severity: str = ""):
    """Log a rule's evaluation result (DETAIL level)."""
    _logger = logging.getLogger("sca.rules")
    msg = "Rule %s: %d files checked, %d matches, %d findings"
    args = [rule_key, files_checked, matches, findings]
    if severity:
        msg += " (%s)"
        args.append(severity)
    _logger.detail(msg, *args,
                   extra={"event": "rule_result", "rule": rule_key,
                           "files": files_checked, "matches": matches,
                           "findings": findings, "severity": severity})


def log_export(file_path: str, size_kb: float, fmt: str = ""):
    """Log a file export (DETAIL level)."""
    _logger = logging.getLogger("sca.export")
    _logger.detail("Export %s: %s (%.1f KB)", fmt, file_path, size_kb,
                   extra={"event": "export", "file": file_path,
                           "size_kb": round(size_kb, 1)})


def log_config_resolve(key: str, value: Any, source: str = "default"):
    """Log the resolution of a configuration key (DETAIL level)."""
    _logger = logging.getLogger("sca.config")
    _logger.detail("Config resolve: %s = %s (from %s)", key, value, source,
                   extra={"event": "config_resolve"})


def log_run_summary(stats: Dict[str, Any]):
    """Log the structured end-of-run summary (INFO level)."""
    _logger = logging.getLogger("sca.runner")
    _logger.info(
        "=== RUN SUMMARY === Duration: %.1fs | Files: %d scanned | "
        "Findings: %d (%dC %dH %dM %dL %dI) | Score: %d%%",
        stats.get("duration", 0),
        stats.get("files_scanned", 0),
        stats.get("total_findings", 0),
        stats.get("critical", 0),
        stats.get("high", 0),
        stats.get("medium", 0),
        stats.get("low", 0),
        stats.get("info", 0),
        stats.get("score", 0),
        extra={"event": "run_summary", **stats}
    )
