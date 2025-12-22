# SLGA models
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Secret:
	value: str
	secret_type: str
	entropy: float
	files: List[str] = field(default_factory=list)
	lines: List[int] = field(default_factory=list)
	commits: List[str] = field(default_factory=list)

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
