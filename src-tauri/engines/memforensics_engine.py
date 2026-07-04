import sys

from engine_memory_acquisition import main as engine1
from engine_os_structure_extractor import main as engine2
from engine_private_exec_memory_analyzer import main as engine3
from engine_execution_evidence_correlator import main as engine4
from engine_execution_flow_reconstructor import main as engine5
from engine_injection_technique_classifier import main as engine6
from engine_forensic_reporting import main as engine7

ENGINES = {
    "1": engine1,
    "2": engine2,
    "3": engine3,
    "4": engine4,
    "5": engine5,
    "6": engine6,
    "7": engine7,
}

def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: memforensics_engine <engine_num> [args...]")
    engine_id = sys.argv[1]
    func = ENGINES.get(engine_id)
    if func is None:
        raise SystemExit(f"Unknown engine id: {engine_id}")
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    func()

if __name__ == "__main__":
    main()
