# SLGA models
from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Secret:
	value: str
	secret_type: str
	entropy: float
	files: List[str] = field(default_factory=list)
	lines: List[int] = field(default_factory=list)
	commits: List[str] = field(default_factory=list)
	path_context: str = 'production'  # 'production' | 'test'
	commit_first_seen: Optional[str] = None   # earliest commit hash where value appeared
	commit_last_seen: Optional[str] = None    # most recent commit hash where value appeared
	source: str = 'file'  # 'file' | 'commit_history' | 'commit_message'

@dataclass
class File:
	path: str
	secrets: List[str] = field(default_factory=list)

@dataclass
class Commit:
	hash: str
	files: List[str] = field(default_factory=list)
	message: Optional[str] = None
	author: Optional[str] = None
	date: Optional[str] = None
	diff: Optional[str] = None
	changed_files: List[str] = field(default_factory=list)
	secrets_found: List[str] = field(default_factory=list)

@dataclass
class Stage:
	name: str
	secrets: List[str] = field(default_factory=list)

@dataclass
class Log:
	path: str
	secrets: List[str] = field(default_factory=list)

@dataclass
class Artifact:
	path: str
	secrets: List[str] = field(default_factory=list)

@dataclass
class PropagationEdge:
	from_node: str
	to_node: str
	edge_type: str
	secret: str


# ---------------------------------------------------------------------------
# Code Symbol Analysis models (tree-sitter + GitPython enrichment)
# ---------------------------------------------------------------------------

@dataclass
class CodeSymbol:
	"""Base class for parsed code symbols."""
	name: str
	file_path: str
	line_start: int
	line_end: int
	scope: str = "module"  # module | class | function

@dataclass
class CodeFunction:
	"""A function or method extracted from source code."""
	name: str
	file_path: str
	line_start: int
	line_end: int
	scope: str = "module"
	params: List[str] = field(default_factory=list)
	return_type: Optional[str] = None
	calls: List[str] = field(default_factory=list)
	decorators: List[str] = field(default_factory=list)
	is_method: bool = False
	parent_class: Optional[str] = None

@dataclass
class CodeClass:
	"""A class definition extracted from source code."""
	name: str
	file_path: str
	line_start: int
	line_end: int
	scope: str = "module"
	methods: List[str] = field(default_factory=list)
	bases: List[str] = field(default_factory=list)
	decorators: List[str] = field(default_factory=list)

@dataclass
class CodeVariable:
	"""A variable assignment or parameter extracted from source code."""
	name: str
	file_path: str
	line_start: int
	line_end: int
	scope: str = "module"
	var_type: str = "assignment"  # assignment | parameter | global
	value_hint: Optional[str] = None  # first 50 chars of assigned value

@dataclass
class CodeImport:
	"""An import statement extracted from source code."""
	module: str
	names: List[str] = field(default_factory=list)
	alias: Optional[str] = None
	file_path: str = ""
	line: int = 0

@dataclass
class CallEdge:
	"""An edge in the call graph: caller invokes callee."""
	caller: str
	callee: str
	file_path: str
	line: int

@dataclass
class FileSymbolSummary:
	"""Aggregated symbol counts for a single file."""
	file_path: str
	language: str = "unknown"
	functions: List[CodeFunction] = field(default_factory=list)
	classes: List[CodeClass] = field(default_factory=list)
	variables: List[CodeVariable] = field(default_factory=list)
	imports: List[CodeImport] = field(default_factory=list)
	call_edges: List[CallEdge] = field(default_factory=list)

	@property
	def function_count(self) -> int:
		return len(self.functions)

	@property
	def class_count(self) -> int:
		return len(self.classes)

	@property
	def variable_count(self) -> int:
		return len(self.variables)

	@property
	def import_count(self) -> int:
		return len(self.imports)

@dataclass
class Contributor:
	"""A git contributor with aggregated statistics."""
	name: str
	email: str = ""
	commits_count: int = 0
	files_touched: List[str] = field(default_factory=list)
	first_seen: Optional[str] = None
	last_seen: Optional[str] = None

@dataclass
class FileGitContext:
	"""Git-level context for a single file (blame, frequency, contributors)."""
	file_path: str
	contributors: List[Contributor] = field(default_factory=list)
	change_frequency: int = 0  # number of commits touching this file
	last_modified: Optional[str] = None
	blame_summary: Dict[str, int] = field(default_factory=dict)  # author → line count
	is_hotspot: bool = False
