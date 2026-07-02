"""axm-fleet — fleet sustainment record spoke for AXM.

Compiles node_record.json documents into genesis-verifiable shards; updates
supersede prior records through the kernel's lineage extension.
"""
from .record_compile import compile_record
from .record_schema import validate_node_record

__all__ = ["compile_record", "validate_node_record"]
__version__ = "0.1.0"
