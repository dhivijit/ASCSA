"""
SLGA Code Parser — Extracts code symbols via tree-sitter AST analysis.

Parses Python, JavaScript, and TypeScript source files to extract
functions, classes, variables, imports, and call-graph edges.  Results
are stored as dataclasses from ``engines.slga.models`` and can be fed
into the Neo4j lineage graph for cross-referencing with secret locations.

Degrades gracefully: if tree-sitter or a language grammar is not
installed the parser returns empty results with a logged warning.
"""

import os
import logging
from typing import List, Dict, Optional, Tuple

from .models import (
    CodeFunction, CodeClass, CodeVariable, CodeImport,
    CallEdge, FileSymbolSummary,
)
from .detector import SKIP_DIRS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language grammar loading (new tree-sitter API)
# ---------------------------------------------------------------------------

_LANGUAGES: Dict[str, object] = {}  # extension -> Language object
_TS_AVAILABLE = False

try:
    from tree_sitter import Language, Parser
    _TS_AVAILABLE = True
except ImportError:
    Language = None  # type: ignore
    Parser = None    # type: ignore
    logger.info("tree-sitter not installed — code symbol analysis disabled")


def _load_language(ext: str):
    """Lazily load and cache a tree-sitter Language for *ext*."""
    if not _TS_AVAILABLE or ext in _LANGUAGES:
        return _LANGUAGES.get(ext)

    try:
        if ext == ".py":
            import tree_sitter_python as tspython
            _LANGUAGES[ext] = Language(tspython.language())
        elif ext in {".js", ".jsx", ".mjs", ".cjs"}:
            import tree_sitter_javascript as tsjavascript
            _LANGUAGES[ext] = Language(tsjavascript.language())
        elif ext in {".ts", ".tsx"}:
            import tree_sitter_typescript as tstypescript
            # tree-sitter-typescript exposes .language_typescript() and .language_tsx()
            if ext == ".tsx":
                _LANGUAGES[ext] = Language(tstypescript.language_tsx())
            else:
                _LANGUAGES[ext] = Language(tstypescript.language_typescript())
    except Exception as e:
        logger.debug(f"Could not load grammar for {ext}: {e}")
        _LANGUAGES[ext] = None  # cache miss so we don't retry

    return _LANGUAGES.get(ext)


# File extensions we know how to parse
PARSEABLE_EXTENSIONS = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

# Map of tree-sitter node types per language family
_PYTHON_NODE_TYPES = {
    "function": "function_definition",
    "class": "class_definition",
    "call": "call",
    "assignment": "assignment",
    "import": {"import_statement", "import_from_statement"},
    "decorator": "decorator",
}

_JS_NODE_TYPES = {
    "function": {"function_declaration", "arrow_function", "method_definition",
                 "function"},
    "class": "class_declaration",
    "call": "call_expression",
    "assignment": {"variable_declarator", "assignment_expression"},
    "import": "import_statement",
    "decorator": "decorator",
}


def _lang_family(ext: str) -> str:
    if ext == ".py":
        return "python"
    return "javascript"  # JS and TS share the same node-type names


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CodeParser:
    """Parse source files using tree-sitter and extract code symbols."""

    def __init__(self):
        if not _TS_AVAILABLE:
            logger.info("CodeParser: tree-sitter unavailable, parsing disabled")

    # -- file-level ---------------------------------------------------------

    def parse_file(self, filepath: str) -> Optional[FileSymbolSummary]:
        """Parse a single source file and return its symbol summary.

        Returns ``None`` if the file extension is unsupported or the
        grammar failed to load.
        """
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in PARSEABLE_EXTENSIONS:
            return None

        lang = _load_language(ext)
        if lang is None:
            return None

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except Exception as e:
            logger.debug(f"Could not read {filepath}: {e}")
            return None

        return self._parse_source(source, filepath, ext, lang)

    # -- directory-level ----------------------------------------------------

    def parse_directory(self, dir_path: str) -> List[FileSymbolSummary]:
        """Recursively parse all supported source files under *dir_path*."""
        if not _TS_AVAILABLE:
            return []

        summaries: List[FileSymbolSummary] = []
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in PARSEABLE_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                summary = self.parse_file(fpath)
                if summary is not None:
                    summaries.append(summary)
        return summaries

    # -- internal parsing ---------------------------------------------------

    def _parse_source(
        self, source: str, filepath: str, ext: str, lang
    ) -> FileSymbolSummary:
        """Parse *source* text into a FileSymbolSummary."""
        parser = Parser()
        parser.language = lang
        tree = parser.parse(bytes(source, "utf-8"))
        root = tree.root_node

        family = _lang_family(ext)

        functions: List[CodeFunction] = []
        classes: List[CodeClass] = []
        variables: List[CodeVariable] = []
        imports: List[CodeImport] = []
        call_edges: List[CallEdge] = []

        # Walk the AST
        self._walk(
            root, source, filepath, family,
            functions, classes, variables, imports, call_edges,
            scope_stack=[],
        )

        lang_label = "python" if family == "python" else ("typescript" if ext in {".ts", ".tsx"} else "javascript")

        return FileSymbolSummary(
            file_path=filepath,
            language=lang_label,
            functions=functions,
            classes=classes,
            variables=variables,
            imports=imports,
            call_edges=call_edges,
        )

    # -- recursive traversal ------------------------------------------------

    def _walk(
        self,
        node,
        source: str,
        filepath: str,
        family: str,
        functions: List[CodeFunction],
        classes: List[CodeClass],
        variables: List[CodeVariable],
        imports: List[CodeImport],
        call_edges: List[CallEdge],
        scope_stack: List[str],
    ):
        ntype = node.type

        # --- Functions / methods ---
        if self._is_function(ntype, family):
            func = self._extract_function(node, source, filepath, family, scope_stack)
            if func:
                functions.append(func)
                # Recurse into function body to find calls
                new_scope = scope_stack + [func.name]
                for child in node.children:
                    self._walk(
                        child, source, filepath, family,
                        functions, classes, variables, imports, call_edges,
                        new_scope,
                    )
                    # Collect call edges inside this function
                    self._collect_calls(child, source, filepath, func.name, call_edges, family)
                return  # children already processed

        # --- Classes ---
        if self._is_class(ntype, family):
            cls = self._extract_class(node, source, filepath, family, scope_stack)
            if cls:
                classes.append(cls)
                new_scope = scope_stack + [cls.name]
                for child in node.children:
                    self._walk(
                        child, source, filepath, family,
                        functions, classes, variables, imports, call_edges,
                        new_scope,
                    )
                return

        # --- Imports ---
        if self._is_import(ntype, family):
            imp = self._extract_import(node, source, filepath, family)
            if imp:
                imports.append(imp)
            return

        # --- Assignments ---
        if self._is_assignment(ntype, family):
            var = self._extract_variable(node, source, filepath, family, scope_stack)
            if var:
                variables.append(var)
            # don't return — may have nested expressions

        # recurse children
        for child in node.children:
            self._walk(
                child, source, filepath, family,
                functions, classes, variables, imports, call_edges,
                scope_stack,
            )

    # -- node type predicates -----------------------------------------------

    @staticmethod
    def _is_function(ntype: str, family: str) -> bool:
        if family == "python":
            return ntype == "function_definition"
        return ntype in {"function_declaration", "arrow_function",
                         "method_definition", "function"}

    @staticmethod
    def _is_class(ntype: str, family: str) -> bool:
        if family == "python":
            return ntype == "class_definition"
        return ntype == "class_declaration"

    @staticmethod
    def _is_import(ntype: str, family: str) -> bool:
        if family == "python":
            return ntype in {"import_statement", "import_from_statement"}
        return ntype == "import_statement"

    @staticmethod
    def _is_assignment(ntype: str, family: str) -> bool:
        if family == "python":
            return ntype == "assignment"
        return ntype in {"variable_declarator", "assignment_expression"}

    # -- extraction helpers -------------------------------------------------

    def _node_text(self, node, source: str) -> str:
        return source[node.start_byte:node.end_byte]

    def _child_by_field(self, node, field: str):
        """Return the first child with the given field name."""
        for child in node.children:
            if node.field_name_for_child(node.children.index(child)) == field:
                return child
        # Fallback: use named field access if available
        try:
            return node.child_by_field_name(field)
        except Exception:
            return None

    def _extract_function(
        self, node, source: str, filepath: str, family: str, scope_stack: List[str]
    ) -> Optional[CodeFunction]:
        """Extract a CodeFunction from a function/method AST node."""
        name_node = self._child_by_field(node, "name")
        name = self._node_text(name_node, source) if name_node else "<anonymous>"

        params: List[str] = []
        params_node = self._child_by_field(node, "parameters") or self._child_by_field(node, "params")
        if params_node:
            for child in params_node.children:
                if child.type in {"identifier", "typed_parameter", "default_parameter",
                                  "formal_parameters", "required_parameter",
                                  "rest_pattern", "assignment_pattern"}:
                    params.append(self._node_text(child, source).split(":")[0].split("=")[0].strip())

        return_type = None
        ret_node = self._child_by_field(node, "return_type")
        if ret_node:
            return_type = self._node_text(ret_node, source).lstrip(":").strip()

        decorators: List[str] = []
        # Look for decorator nodes preceding this node
        if node.prev_named_sibling and node.prev_named_sibling.type == "decorator":
            sib = node.prev_named_sibling
            while sib and sib.type == "decorator":
                decorators.append(self._node_text(sib, source).lstrip("@").strip())
                sib = sib.prev_named_sibling

        is_method = bool(scope_stack and any(
            # parent scope is a class
            True for _ in []
        )) or node.type == "method_definition"

        parent_class = scope_stack[-1] if scope_stack else None
        # Check if parent scope looks like a class (crude heuristic — the walk
        # pushes class names onto scope_stack before walking children).
        if scope_stack:
            is_method = True  # inside something
        if node.type == "method_definition":
            is_method = True

        # Collect names of functions called inside this function body
        calls: List[str] = []
        body = self._child_by_field(node, "body")
        if body:
            self._collect_call_names(body, source, calls, family)

        return CodeFunction(
            name=name,
            file_path=filepath,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            scope="method" if is_method else "module",
            params=params,
            return_type=return_type,
            calls=calls,
            decorators=decorators,
            is_method=is_method,
            parent_class=parent_class,
        )

    def _extract_class(
        self, node, source: str, filepath: str, family: str, scope_stack: List[str]
    ) -> Optional[CodeClass]:
        name_node = self._child_by_field(node, "name")
        name = self._node_text(name_node, source) if name_node else "<anonymous>"

        bases: List[str] = []
        if family == "python":
            arg_list = self._child_by_field(node, "superclasses")
            if arg_list:
                for child in arg_list.children:
                    if child.type == "identifier":
                        bases.append(self._node_text(child, source))
        else:
            heritage = None
            for child in node.children:
                if child.type == "class_heritage":
                    heritage = child
                    break
            if heritage:
                for child in heritage.children:
                    if child.type == "identifier":
                        bases.append(self._node_text(child, source))

        # Method names (collected during walk, but we can pre-scan the body)
        methods: List[str] = []
        body_node = self._child_by_field(node, "body")
        if body_node:
            for child in body_node.children:
                if self._is_function(child.type, family):
                    mn = self._child_by_field(child, "name")
                    if mn:
                        methods.append(self._node_text(mn, source))

        decorators: List[str] = []
        if node.prev_named_sibling and node.prev_named_sibling.type == "decorator":
            sib = node.prev_named_sibling
            while sib and sib.type == "decorator":
                decorators.append(self._node_text(sib, source).lstrip("@").strip())
                sib = sib.prev_named_sibling

        return CodeClass(
            name=name,
            file_path=filepath,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            scope="module",
            methods=methods,
            bases=bases,
            decorators=decorators,
        )

    def _extract_import(
        self, node, source: str, filepath: str, family: str
    ) -> Optional[CodeImport]:
        text = self._node_text(node, source)
        module = ""
        names: List[str] = []
        alias: Optional[str] = None

        if family == "python":
            if node.type == "import_from_statement":
                mod_node = self._child_by_field(node, "module_name")
                if mod_node:
                    module = self._node_text(mod_node, source)
                # extract imported names
                for child in node.children:
                    if child.type == "dotted_name" and child != mod_node:
                        names.append(self._node_text(child, source))
                    elif child.type == "aliased_import":
                        name_n = self._child_by_field(child, "name")
                        alias_n = self._child_by_field(child, "alias")
                        if name_n:
                            names.append(self._node_text(name_n, source))
                        if alias_n:
                            alias = self._node_text(alias_n, source)
            else:
                # plain import
                for child in node.children:
                    if child.type == "dotted_name":
                        module = self._node_text(child, source)
                    elif child.type == "aliased_import":
                        name_n = self._child_by_field(child, "name")
                        alias_n = self._child_by_field(child, "alias")
                        if name_n:
                            module = self._node_text(name_n, source)
                        if alias_n:
                            alias = self._node_text(alias_n, source)
        else:
            # JS/TS import — simplified extraction
            for child in node.children:
                if child.type == "string":
                    module = self._node_text(child, source).strip("\"'")
                elif child.type == "import_clause":
                    names.append(self._node_text(child, source))

        if not module and not names:
            # Fallback: just store raw text
            module = text.strip()

        return CodeImport(
            module=module,
            names=names,
            alias=alias,
            file_path=filepath,
            line=node.start_point[0] + 1,
        )

    def _extract_variable(
        self, node, source: str, filepath: str, family: str, scope_stack: List[str]
    ) -> Optional[CodeVariable]:
        if family == "python":
            # assignment: left = right
            left = node.children[0] if node.children else None
            right = node.children[-1] if len(node.children) > 1 else None
        else:
            # variable_declarator: name = value
            left = self._child_by_field(node, "name")
            right = self._child_by_field(node, "value")

        if left is None:
            return None

        name = self._node_text(left, source).strip()
        # Skip complex destructuring patterns
        if len(name) > 80 or "\n" in name:
            return None

        value_hint = None
        if right:
            raw = self._node_text(right, source)
            value_hint = raw[:50] if len(raw) > 50 else raw

        scope = "function" if scope_stack else "module"
        var_type = "assignment"

        return CodeVariable(
            name=name,
            file_path=filepath,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            scope=scope,
            var_type=var_type,
            value_hint=value_hint,
        )

    # -- call graph helpers ------------------------------------------------

    def _collect_call_names(
        self, node, source: str, calls: List[str], family: str
    ):
        """Recursively collect callee names from call expressions."""
        call_type = "call" if family == "python" else "call_expression"
        if node.type == call_type:
            callee = node.children[0] if node.children else None
            if callee:
                name = self._node_text(callee, source)
                # Simplify attribute access: keep last segment (e.g. os.path.join -> join)
                if "." in name:
                    name = name.rsplit(".", 1)[-1]
                if name and len(name) < 100:
                    calls.append(name)

        for child in node.children:
            self._collect_call_names(child, source, calls, family)

    def _collect_calls(
        self, node, source: str, filepath: str,
        caller_name: str, call_edges: List[CallEdge], family: str,
    ):
        """Build CallEdge objects from call expressions inside *caller_name*."""
        call_type = "call" if family == "python" else "call_expression"
        if node.type == call_type:
            callee_node = node.children[0] if node.children else None
            if callee_node:
                callee = self._node_text(callee_node, source)
                if "." in callee:
                    callee = callee.rsplit(".", 1)[-1]
                if callee and len(callee) < 100:
                    call_edges.append(CallEdge(
                        caller=caller_name,
                        callee=callee,
                        file_path=filepath,
                        line=node.start_point[0] + 1,
                    ))

        for child in node.children:
            self._collect_calls(child, source, filepath, caller_name, call_edges, family)
