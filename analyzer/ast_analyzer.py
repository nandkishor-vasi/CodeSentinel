"""Code-quality analysis based on Python's ``ast`` module.

The source is parsed, never executed. Checks implemented:

* CS-Q001  missing function docstring
* CS-Q002  too many function parameters
* CS-Q003  broad / bare exception handling
* CS-Q004  high cyclomatic complexity
* CS-Q005  overly long function
* CS-Q006  deeply nested control flow
"""

from __future__ import annotations

import ast

from .models import SOURCE_QUALITY, Finding, snippet_from_source

MAX_PARAMS = 5
MAX_COMPLEXITY = 10
MAX_FUNCTION_LINES = 60
MAX_NESTING = 4

_FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)
_BROAD_EXCEPTIONS = {"Exception", "BaseException"}

RULES: dict[str, tuple[str, str, str]] = {
    "CS-Q001": (
        "Missing function docstring",
        "Documentation",
        "Add a docstring that states what the function does, its parameters and its return value.",
    ),
    "CS-Q002": (
        "Too many function parameters",
        "Function Design",
        "Group related parameters into a dataclass or dict, or split the function into smaller ones.",
    ),
    "CS-Q003": (
        "Broad exception handling",
        "Error Handling",
        "Catch the specific exceptions you expect (for example OSError, ValueError) and log or re-raise them.",
    ),
    "CS-Q004": (
        "High cyclomatic complexity",
        "Complexity",
        "Extract branches into helper functions, use early returns and lookup tables to reduce decision points.",
    ),
    "CS-Q005": (
        "Function is too long",
        "Maintainability",
        "Split the function into smaller, single-purpose functions that are easier to test and review.",
    ),
    "CS-Q006": (
        "Deeply nested control flow",
        "Complexity",
        "Flatten nesting with guard clauses (early return/continue) or move inner blocks into helper functions.",
    ),
}


def _finding(
    rule_id: str,
    severity: str,
    line: int,
    description: str,
    lines: list[str],
    end_line: int | None = None,
) -> Finding:
    title, category, remediation = RULES[rule_id]
    return Finding(
        source=SOURCE_QUALITY,
        rule_id=rule_id,
        title=f"{rule_id}: {title}",
        severity=severity,
        confidence="HIGH",  # AST checks are deterministic
        line=line,
        end_line=end_line or line,
        category=category,
        description=description,
        remediation=remediation,
        code_snippet=snippet_from_source(lines, line, end_line or line),
    )


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _count_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = node.args
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    count = len([n for n in names if n not in ("self", "cls")])
    return count + (1 if args.vararg else 0) + (1 if args.kwarg else 0)


def cyclomatic_complexity(node: ast.AST) -> int:
    """McCabe-style complexity of a function body (nested scopes are excluded)."""
    total = 1
    stack = list(ast.iter_child_nodes(node))
    while stack:
        current = stack.pop()
        if isinstance(current, _SCOPE_TYPES):
            continue
        if isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)):
            total += 1
        elif isinstance(current, ast.BoolOp):
            total += len(current.values) - 1
        elif isinstance(current, ast.comprehension):
            total += 1 + len(current.ifs)
        stack.extend(ast.iter_child_nodes(current))
    return total


def max_nesting(node: ast.AST, depth: int = 0) -> int:
    """Deepest nesting of control-flow blocks. ``elif`` chains do not add depth."""
    deepest = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_TYPES):
            continue
        is_elif = (
            isinstance(node, ast.If)
            and isinstance(child, ast.If)
            and len(node.orelse) == 1
            and node.orelse[0] is child
        )
        step = 1 if isinstance(child, _NESTING_NODES) and not is_elif else 0
        deepest = max(deepest, max_nesting(child, depth + step))
    return deepest


def _signature_end(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Last line of the ``def`` header (stops before the first body statement)."""
    first_body = node.body[0].lineno if node.body else node.lineno
    return max(node.lineno, first_body - 1)


def _check_function(node: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    name = node.name
    header_end = _signature_end(node)

    if not _is_dunder(name) and ast.get_docstring(node) is None:
        findings.append(
            _finding("CS-Q001", "LOW", node.lineno, f"Function '{name}' has no docstring.", lines, header_end)
        )

    params = _count_params(node)
    if params > MAX_PARAMS:
        severity = "MEDIUM" if params > 7 else "LOW"
        findings.append(
            _finding(
                "CS-Q002", severity, node.lineno,
                f"Function '{name}' takes {params} parameters (recommended maximum: {MAX_PARAMS}).",
                lines, header_end,
            )
        )

    complexity = cyclomatic_complexity(node)
    if complexity > MAX_COMPLEXITY:
        severity = "HIGH" if complexity > 20 else "MEDIUM"
        findings.append(
            _finding(
                "CS-Q004", severity, node.lineno,
                f"Function '{name}' has a cyclomatic complexity of {complexity} (recommended maximum: {MAX_COMPLEXITY}).",
                lines, header_end,
            )
        )

    length = (node.end_lineno or node.lineno) - node.lineno + 1
    if length > MAX_FUNCTION_LINES:
        severity = "MEDIUM" if length > 120 else "LOW"
        findings.append(
            _finding(
                "CS-Q005", severity, node.lineno,
                f"Function '{name}' is {length} lines long (recommended maximum: {MAX_FUNCTION_LINES}).",
                lines, header_end,
            )
        )

    depth = max_nesting(node)
    if depth > MAX_NESTING:
        findings.append(
            _finding(
                "CS-Q006", "MEDIUM", node.lineno,
                f"Function '{name}' nests control flow {depth} levels deep (recommended maximum: {MAX_NESTING}).",
                lines, header_end,
            )
        )
    return findings


def _handler_names(handler_type: ast.expr | None) -> list[str]:
    if handler_type is None:
        return []
    elements = handler_type.elts if isinstance(handler_type, ast.Tuple) else [handler_type]
    names = []
    for element in elements:
        if isinstance(element, ast.Name):
            names.append(element.id)
        elif isinstance(element, ast.Attribute):
            names.append(element.attr)
    return names


def _check_handler(node: ast.ExceptHandler, lines: list[str]) -> Finding | None:
    if node.type is None:
        return _finding(
            "CS-Q003", "MEDIUM", node.lineno,
            "Bare 'except:' also catches SystemExit and KeyboardInterrupt and hides real errors.",
            lines,
        )
    broad = [n for n in _handler_names(node.type) if n in _BROAD_EXCEPTIONS]
    if broad:
        severity = "MEDIUM" if "BaseException" in broad else "LOW"
        return _finding(
            "CS-Q003", severity, node.lineno,
            f"'except {broad[0]}' is too broad; catch the specific exceptions you can handle.",
            lines,
        )
    return None


def analyze_source(code: str, lines: list[str] | None = None) -> list[Finding]:
    """Parse ``code`` and return code-quality findings.

    Raises SyntaxError if the source is not valid Python (the code is only parsed).
    """
    source_lines = lines if lines is not None else code.splitlines()
    tree = ast.parse(code)

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, _FUNC_TYPES):
            findings.extend(_check_function(node, source_lines))
        elif isinstance(node, ast.ExceptHandler):
            handler_finding = _check_handler(node, source_lines)
            if handler_finding:
                findings.append(handler_finding)

    findings.sort(key=lambda f: (f.line, f.rule_id))
    return findings
