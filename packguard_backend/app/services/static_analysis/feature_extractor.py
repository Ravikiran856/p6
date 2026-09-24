"""
feature_extractor.py
=====================
Static (non-executing) analysis of a Python package's source tree.

Given a directory containing a package's `.py` files (already downloaded
and unpacked by `pypi_client.py` — never executed), this module walks each
file's Abstract Syntax Tree (AST) plus its raw text to derive a fixed-length
numeric feature vector describing security-relevant behaviour.

Additionally, this module records a structured finding for every matched AST pattern:
{
    "indicator_id": str,
    "category": str,
    "line_number": int,
    "code_snippet": str,
    "file_path": str,
}

Findings are categorized according to a 7-category security taxonomy:
1. Execution
2. Persistence
3. Defense Evasion
4. Exfiltration
5. Discovery
6. Command & Control
7. Metadata Manipulation

Install scripts (`setup.py` and `__init__.py`) are weighted with INSTALL_SCRIPT_WEIGHT = 1.5.
"""

from __future__ import annotations

import ast
import os
import re
import tokenize
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import numpy as np

# --------------------------------------------------------------------------- #
# Fixed feature ordering — MUST match the column order used in train_model.py
# and predict.py. Keeping a single source of truth avoids silent column
# mismatches between training and inference.
# --------------------------------------------------------------------------- #
FEATURE_ORDER: List[str] = [
    "has_network_call",
    "has_file_system_access",
    "has_command_execution",
    "has_credential_access",
    "has_code_obfuscation",
    "has_dynamic_imports",
    "external_url_count",
    "suspicious_dependency_count",
]

# --------------------------------------------------------------------------- #
# 7-Category Security Taxonomy
# --------------------------------------------------------------------------- #
CATEGORY_EXECUTION = "Execution"
CATEGORY_PERSISTENCE = "Persistence"
CATEGORY_DEFENSE_EVASION = "Defense Evasion"
CATEGORY_EXFILTRATION = "Exfiltration"
CATEGORY_DISCOVERY = "Discovery"
CATEGORY_COMMAND_AND_CONTROL = "Command & Control"
CATEGORY_METADATA_MANIPULATION = "Metadata Manipulation"

TAXONOMY_CATEGORIES = {
    CATEGORY_EXECUTION,
    CATEGORY_PERSISTENCE,
    CATEGORY_DEFENSE_EVASION,
    CATEGORY_EXFILTRATION,
    CATEGORY_DISCOVERY,
    CATEGORY_COMMAND_AND_CONTROL,
    CATEGORY_METADATA_MANIPULATION,
}

# --------------------------------------------------------------------------- #
# Install-Script Weighting Configuration
# --------------------------------------------------------------------------- #
INSTALL_SCRIPT_WEIGHT: float = 1.5
INSTALL_SCRIPTS: Set[str] = {"setup.py", "__init__.py"}


def is_install_script_path(file_path: str) -> bool:
    """Check if file_path points to an install script / hook (setup.py, __init__.py)."""
    norm = file_path.replace("\\", "/").lower()
    base = os.path.basename(norm)
    return base in INSTALL_SCRIPTS


def is_install_script_finding(finding: Dict[str, Any]) -> bool:
    """Check if a finding was detected in an install script or hook."""
    file_path = finding.get("file_path", "")
    if is_install_script_path(file_path):
        return True
    if finding.get("category") == CATEGORY_PERSISTENCE:
        return True
    indicator = finding.get("indicator_id", "")
    if indicator.startswith("PERSIST_"):
        return True
    return False


# --------------------------------------------------------------------------- #
# Reference signatures for static AST analysis
# --------------------------------------------------------------------------- #
NETWORK_MODULES = {
    "socket", "requests", "urllib", "urllib2", "http", "httplib",
    "ftplib", "telnetlib", "aiohttp", "httpx",
}
NETWORK_ATTRS = {"urlopen", "get", "post", "put", "connect", "create_connection"}

FS_MODULES = {"shutil", "os", "pathlib", "tempfile"}
FS_FUNCS = {"open", "remove", "unlink", "rmtree", "rename", "chmod", "chown"}

EXEC_MODULES = {"subprocess", "os", "pty", "commands"}
EXEC_FUNCS = {
    "system", "popen", "call", "run", "Popen", "check_call",
    "check_output", "spawn", "execv", "execve",
}
DANGEROUS_BUILTINS = {"eval", "exec", "compile"}

CREDENTIAL_PATH_PATTERNS = re.compile(
    r"(\.aws/credentials|\.ssh/id_rsa|\.ssh/|\.netrc|\.env\b|"
    r"AKIA[0-9A-Z]{16}|id_dsa|id_ecdsa)",
    re.IGNORECASE,
)
CREDENTIAL_CALL_ATTRS = {"environ", "getenv"}

DYNAMIC_IMPORT_FUNCS = {"import_module", "__import__"}

URL_REGEX = re.compile(r"https?://[^\s'\"<>]+")

TRUSTED_MODULES_FOR_OBFUSCATION = {"base64", "binascii", "codecs", "marshal", "zlib"}


def _string_concat_depth(node: ast.BinOp) -> int:
    """Counts how many chained `+` operations sit directly under this BinOp."""
    depth = 1
    for child in (node.left, node.right):
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
            depth += _string_concat_depth(child)
    return depth


def _extract_comments_with_lines(source: str) -> List[Tuple[int, str]]:
    """Pull comments with 1-based line numbers via `tokenize`."""
    comments = []
    try:
        tokens = tokenize.generate_tokens(iter(source.splitlines(keepends=True)).__next__)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                comments.append((tok.start[0], tok.string))
    except (tokenize.TokenizeError, SyntaxError, IndentationError):
        pass  # best-effort; malformed/partial files shouldn't crash the scan
    return comments


def _iter_python_files(package_dir: str) -> Iterable[str]:
    for root, _dirs, files in os.walk(package_dir):
        for fname in files:
            if fname.endswith(".py"):
                yield os.path.join(root, fname)


def _load_dependency_names(package_dir: str) -> Set[str]:
    """
    Best-effort extraction of declared dependency names from whichever
    manifest the package ships (setup.py install_requires, requirements.txt,
    or pyproject.toml [project.dependencies]).
    """
    deps: Set[str] = set()
    name_pattern = re.compile(r"^[A-Za-z0-9_.\-]+")

    req_txt = os.path.join(package_dir, "requirements.txt")
    if os.path.isfile(req_txt):
        with open(req_txt, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    match = name_pattern.match(line)
                    if match:
                        deps.add(match.group(0).lower())

    setup_py = os.path.join(package_dir, "setup.py")
    if os.path.isfile(setup_py):
        with open(setup_py, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        for match in re.finditer(r"install_requires\s*=\s*\[(.*?)\]", text, re.DOTALL):
            for item in re.findall(r"['\"]([^'\"]+)['\"]", match.group(1)):
                dep_name = name_pattern.match(item)
                if dep_name:
                    deps.add(dep_name.group(0).lower())

    return deps


class _StructuredASTVisitor(ast.NodeVisitor):
    """
    AST Walker that captures per-line security findings and categorizes
    them into the 7-category taxonomy.
    """

    def __init__(self, rel_path: str, source_lines: List[str]) -> None:
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.is_install_script = is_install_script_path(rel_path)

        # Evidence aggregates for feature extraction
        self.imported_modules: Set[str] = set()
        self.called_names: Set[str] = set()
        self.called_attrs: Set[str] = set()
        self.string_literals: List[Tuple[int, str]] = []
        self.has_base64_import: bool = False
        self.has_exec_or_eval_call: bool = False
        self.max_consecutive_string_concats: int = 0
        self.findings: List[Dict[str, Any]] = []

    def _get_snippet(self, lineno: int) -> str:
        idx = lineno - 1
        if 0 <= idx < len(self.source_lines):
            line = self.source_lines[idx].strip()
            return line[:120] if len(line) > 120 else line
        return ""

    def _record_finding(
        self,
        indicator_id: str,
        category: str,
        line_number: int,
        title: Optional[str] = None,
        severity: str = "medium",
    ) -> None:
        snippet = self._get_snippet(line_number)
        finding = {
            "indicator_id": indicator_id,
            "category": category,
            "line_number": int(line_number),
            "code_snippet": snippet,
            "file_path": self.rel_path,
            "title": title or indicator_id.replace("_", " ").title(),
            "severity": severity,
        }
        self.findings.append(finding)

    def visit_Import(self, node: ast.Import) -> None:
        lineno = getattr(node, "lineno", 1)
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            self.imported_modules.add(top_level)
            if top_level in TRUSTED_MODULES_FOR_OBFUSCATION:
                self.has_base64_import = True
            if top_level in EXEC_MODULES:
                category = CATEGORY_PERSISTENCE if self.is_install_script else CATEGORY_EXECUTION
                indicator = "PERSIST_INSTALL_HOOK" if self.is_install_script else "EXEC_SUBPROCESS"
                self._record_finding(
                    indicator,
                    category,
                    lineno,
                    title=f"Execution Module Import ({top_level})",
                    severity="high" if self.is_install_script else "medium",
                )
            elif top_level in NETWORK_MODULES:
                category = CATEGORY_COMMAND_AND_CONTROL if top_level == "socket" else CATEGORY_EXFILTRATION
                indicator = "C2_RAW_SOCKET" if top_level == "socket" else "EXFIL_NETWORK_CALL"
                self._record_finding(
                    indicator,
                    category,
                    lineno,
                    title=f"Network Communication Module ({top_level})",
                    severity="medium",
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        lineno = getattr(node, "lineno", 1)
        if node.module:
            top_level = node.module.split(".")[0]
            self.imported_modules.add(top_level)
            if top_level in TRUSTED_MODULES_FOR_OBFUSCATION:
                self.has_base64_import = True

            # Detect setuptools install hook imports in setup.py (persistence)
            if self.is_install_script and "setuptools.command" in node.module:
                self._record_finding(
                    "PERSIST_CUSTOM_CMDCLASS",
                    CATEGORY_PERSISTENCE,
                    lineno,
                    title="Setup.py Install Command Hook",
                    severity="high",
                )
            elif top_level in EXEC_MODULES:
                category = CATEGORY_PERSISTENCE if self.is_install_script else CATEGORY_EXECUTION
                self._record_finding(
                    "EXEC_SUBPROCESS",
                    category,
                    lineno,
                    title=f"Subprocess Execution Import ({node.module})",
                    severity="high" if self.is_install_script else "medium",
                )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        lineno = getattr(node, "lineno", 1)
        # In setup.py, custom classes inheriting from install/develop are classic persistence droppers
        if self.is_install_script:
            for base in node.bases:
                base_name = ""
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name in ("install", "develop", "build_py"):
                    self._record_finding(
                        "PERSIST_CUSTOM_CMDCLASS",
                        CATEGORY_PERSISTENCE,
                        lineno,
                        title=f"Custom Install Hook Class '{node.name}'",
                        severity="high",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        lineno = getattr(node, "lineno", 1)
        func = node.func

        # 1. Bare calls: eval(...), exec(...), open(...)
        if isinstance(func, ast.Name):
            func_name = func.id
            self.called_names.add(func_name)
            if func_name in DANGEROUS_BUILTINS:
                self.has_exec_or_eval_call = True
                category = CATEGORY_PERSISTENCE if self.is_install_script else CATEGORY_EXECUTION
                self._record_finding(
                    "EXEC_DYNAMIC_CODE",
                    category,
                    lineno,
                    title=f"Dynamic Code Evaluation ({func_name})",
                    severity="high",
                )
            elif func_name == "open":
                self._record_finding(
                    "DISCOVERY_FILE_SYSTEM",
                    CATEGORY_DISCOVERY,
                    lineno,
                    title="File System Access (open)",
                    severity="low",
                )
            elif func_name in DYNAMIC_IMPORT_FUNCS:
                self._record_finding(
                    "EVASION_DYNAMIC_IMPORT",
                    CATEGORY_DEFENSE_EVASION,
                    lineno,
                    title=f"Dynamic Module Resolution ({func_name})",
                    severity="medium",
                )

        # 2. Attribute calls: os.system(...), subprocess.Popen(...), etc.
        elif isinstance(func, ast.Attribute):
            attr_name = func.attr
            self.called_attrs.add(attr_name)

            if attr_name in DANGEROUS_BUILTINS:
                self.has_exec_or_eval_call = True
                category = CATEGORY_PERSISTENCE if self.is_install_script else CATEGORY_EXECUTION
                self._record_finding(
                    "EXEC_DYNAMIC_CODE",
                    category,
                    lineno,
                    title=f"Dynamic Code Execution (builtins.{attr_name})",
                    severity="high",
                )
            elif attr_name in EXEC_FUNCS:
                category = CATEGORY_PERSISTENCE if self.is_install_script else CATEGORY_EXECUTION
                indicator = "PERSIST_INSTALL_HOOK" if self.is_install_script else "EXEC_OS_COMMAND"
                self._record_finding(
                    indicator,
                    category,
                    lineno,
                    title=f"Command / Process Execution ({attr_name})",
                    severity="high" if self.is_install_script else "medium",
                )
            elif attr_name in FS_FUNCS:
                self._record_finding(
                    "DISCOVERY_FILE_SYSTEM",
                    CATEGORY_DISCOVERY,
                    lineno,
                    title=f"File System Manipulation ({attr_name})",
                    severity="medium" if attr_name in ("rmtree", "unlink", "remove", "chmod") else "low",
                )
            elif attr_name in NETWORK_ATTRS:
                category = CATEGORY_EXFILTRATION
                indicator = "EXFIL_NETWORK_CALL"
                if attr_name in ("connect", "create_connection"):
                    category = CATEGORY_COMMAND_AND_CONTROL
                    indicator = "C2_RAW_SOCKET"
                self._record_finding(
                    indicator,
                    category,
                    lineno,
                    title=f"Network Call ({attr_name})",
                    severity="medium",
                )
            elif attr_name in CREDENTIAL_CALL_ATTRS:
                self._record_finding(
                    "DISCOVERY_CREDENTIALS",
                    CATEGORY_DISCOVERY,
                    lineno,
                    title=f"Environment Secret Access ({attr_name})",
                    severity="medium",
                )
            elif attr_name in DYNAMIC_IMPORT_FUNCS:
                self._record_finding(
                    "EVASION_DYNAMIC_IMPORT",
                    CATEGORY_DEFENSE_EVASION,
                    lineno,
                    title=f"Dynamic Module Resolution ({attr_name})",
                    severity="medium",
                )

        # Check for setup(..., cmdclass=...) persistence hook
        if self.is_install_script:
            for kw in node.keywords:
                if kw.arg == "cmdclass":
                    self._record_finding(
                        "PERSIST_INSTALL_HOOK",
                        CATEGORY_PERSISTENCE,
                        lineno,
                        title="Setup.py Custom 'cmdclass' Hook",
                        severity="high",
                    )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        lineno = getattr(node, "lineno", 1)
        if isinstance(node.value, str):
            val = node.value
            self.string_literals.append((lineno, val))

            # Credential path checks in string literals
            if CREDENTIAL_PATH_PATTERNS.search(val):
                self._record_finding(
                    "DISCOVERY_CREDENTIALS",
                    CATEGORY_DISCOVERY,
                    lineno,
                    title="Hardcoded Sensitive Credential Path Pattern",
                    severity="high",
                )

            # External URL finding
            urls = URL_REGEX.findall(val)
            for url in urls:
                # Filter out standard python documentation & schemas
                if not any(ign in url.lower() for ign in ("python.org", "w3.org", "schema.org", "pypi.org")):
                    self._record_finding(
                        "C2_EXTERNAL_URL",
                        CATEGORY_COMMAND_AND_CONTROL,
                        lineno,
                        title=f"External Remote URL Endpoint ({url[:45]}...)",
                        severity="medium",
                    )
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        lineno = getattr(node, "lineno", 1)
        if isinstance(node.op, ast.Add):
            depth = _string_concat_depth(node)
            self.max_consecutive_string_concats = max(
                self.max_consecutive_string_concats, depth
            )
            if depth >= 4:
                self._record_finding(
                    "EVASION_STRING_CONCAT",
                    CATEGORY_DEFENSE_EVASION,
                    lineno,
                    title=f"Deep String Concatenation Chaining (depth={depth})",
                    severity="high",
                )
        self.generic_visit(node)


class FeatureExtractionResult(dict):
    """
    Subclasses dict so that existing callers, assertions, and dictionary operations
    (e.g., `set(features.keys()) == set(FEATURE_ORDER)`, `features['has_network_call']`)
    continue to work seamlessly with 100% backward compatibility, while structured
    findings are preserved in the `.findings` attribute.
    """

    def __init__(self, features: Dict[str, float], findings: List[Dict[str, Any]]):
        super().__init__(features)
        self.findings: List[Dict[str, Any]] = findings

    def to_dict(self) -> Dict[str, float]:
        return {k: v for k, v in self.items()}


def extract_features(
    package_dir: str,
    trusted_top_packages: Set[str],
) -> FeatureExtractionResult:
    """
    Run static AST analysis over every `.py` file under `package_dir` and return
    a FeatureExtractionResult containing the FEATURE_ORDER numeric dictionary
    and the structured security findings list.
    """
    all_findings: List[Dict[str, Any]] = []
    imported_modules: Set[str] = set()
    called_names: Set[str] = set()
    called_attrs: Set[str] = set()
    string_literals: List[str] = []
    comments_all: List[Tuple[str, int, str]] = []  # (rel_path, lineno, text)
    has_base64_import = False
    has_exec_or_eval_call = False
    max_consecutive_string_concats = 0

    for filepath in _iter_python_files(package_dir):
        rel_path = os.path.relpath(filepath, package_dir).replace("\\", "/")
        if rel_path.startswith("./"):
            rel_path = rel_path[2:]

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, ValueError):
            continue

        source_lines = source.splitlines()
        visitor = _StructuredASTVisitor(rel_path, source_lines)
        visitor.visit(tree)

        imported_modules |= visitor.imported_modules
        called_names |= visitor.called_names
        called_attrs |= visitor.called_attrs
        for _ln, s in visitor.string_literals:
            string_literals.append(s)

        has_base64_import = has_base64_import or visitor.has_base64_import
        has_exec_or_eval_call = has_exec_or_eval_call or visitor.has_exec_or_eval_call
        max_consecutive_string_concats = max(
            max_consecutive_string_concats, visitor.max_consecutive_string_concats
        )
        all_findings.extend(visitor.findings)

        # Comments check
        for c_lineno, c_text in _extract_comments_with_lines(source):
            comments_all.append((rel_path, c_lineno, c_text))
            for url in URL_REGEX.findall(c_text):
                if not any(ign in url.lower() for ign in ("python.org", "w3.org", "schema.org", "pypi.org")):
                    all_findings.append({
                        "indicator_id": "C2_EXTERNAL_URL",
                        "category": CATEGORY_COMMAND_AND_CONTROL,
                        "line_number": c_lineno,
                        "code_snippet": c_text.strip()[:120],
                        "file_path": rel_path,
                        "title": f"External Remote URL in Comment ({url[:45]}...)",
                        "severity": "medium",
                    })

    # Combined obfuscation finding: base64 + exec
    if has_base64_import and has_exec_or_eval_call:
        # Check if already added
        if not any(f["indicator_id"] == "EVASION_OBFUSCATED_PAYLOAD" for f in all_findings):
            all_findings.append({
                "indicator_id": "EVASION_OBFUSCATED_PAYLOAD",
                "category": CATEGORY_DEFENSE_EVASION,
                "line_number": 1,
                "code_snippet": "import base64 ... exec(...) payload decode-and-execute",
                "file_path": "package_root",
                "title": "Payload Obfuscation (Decode & Execute Pattern)",
                "severity": "high",
            })

    # --- Derive binary and count feature values ---
    has_network_call = bool(
        imported_modules & NETWORK_MODULES or called_attrs & NETWORK_ATTRS
    )

    has_file_system_access = bool(
        (imported_modules & FS_MODULES and called_attrs & FS_FUNCS)
        or "open" in called_names
    )

    has_command_execution = bool(
        (imported_modules & EXEC_MODULES and called_attrs & EXEC_FUNCS)
        or called_names & DANGEROUS_BUILTINS
    )

    joined_strings = " ".join(string_literals)
    has_credential_access = bool(
        CREDENTIAL_PATH_PATTERNS.search(joined_strings)
        or ("os" in imported_modules and called_attrs & CREDENTIAL_CALL_ATTRS)
    )

    has_code_obfuscation = bool(
        (has_base64_import and has_exec_or_eval_call)
        or max_consecutive_string_concats >= 4
    )

    has_dynamic_imports = bool(
        "importlib" in imported_modules
        or "__import__" in called_names
        or called_attrs & DYNAMIC_IMPORT_FUNCS
    )

    url_hits = URL_REGEX.findall(joined_strings) + [
        u for _rp, _ln, c in comments_all for u in URL_REGEX.findall(c)
    ]
    external_url_count = len(set(url_hits))

    # Dependencies
    declared_deps = _load_dependency_names(package_dir)
    suspicious_deps = {d for d in declared_deps if d not in trusted_top_packages}
    suspicious_dependency_count = len(suspicious_deps)

    for dep in suspicious_deps:
        all_findings.append({
            "indicator_id": "META_SUSPICIOUS_DEP",
            "category": CATEGORY_METADATA_MANIPULATION,
            "line_number": 1,
            "code_snippet": f"requires: {dep}",
            "file_path": "requirements.txt",
            "title": f"Untrusted Dependency Declared ('{dep}')",
            "severity": "medium",
        })

    feature_dict: Dict[str, float] = {
        "has_network_call": float(has_network_call),
        "has_file_system_access": float(has_file_system_access),
        "has_command_execution": float(has_command_execution),
        "has_credential_access": float(has_credential_access),
        "has_code_obfuscation": float(has_code_obfuscation),
        "has_dynamic_imports": float(has_dynamic_imports),
        "external_url_count": float(external_url_count),
        "suspicious_dependency_count": float(suspicious_dependency_count),
    }

    ordered_dict = {name: feature_dict[name] for name in FEATURE_ORDER}
    return FeatureExtractionResult(ordered_dict, all_findings)


def to_vector(feature_dict: Dict[str, float]) -> np.ndarray:
    """Convert a feature dict (any key order) into a fixed-order np.ndarray."""
    return np.array([feature_dict[name] for name in FEATURE_ORDER], dtype=float)


if __name__ == "__main__":
    import sys

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    trusted = {"requests", "flask", "numpy", "click", "urllib3"}
    res = extract_features(target_dir, trusted)
    print("Feature dict:", dict(res))
    print(f"Total findings: {len(res.findings)}")
    for f in res.findings[:5]:
        print(f" - [{f['category']}] Line {f['line_number']} in {f['file_path']} ({f['indicator_id']}): {f['code_snippet']}")
