#!/usr/bin/env python3
import sys
import subprocess
import os

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    engines = {
        '1': 'engine_memory_acquisition.py',
        '2': 'engine_os_structure_extractor.py', 
        '3': 'engine_private_exec_memory_analyzer.py',
        '4': 'engine_execution_evidence_correlator.py',
        '5': 'engine_execution_flow_reconstructor.py',
        '6': 'engine_injection_technique_classifier.py',
        '7': 'engine_forensic_reporting.py',
    }
    
    engine_num = sys.argv[1]
    args = sys.argv[2:]
    
    engine_script = os.path.join(script_dir, engines[engine_num])
    result = subprocess.run(
        [sys.executable, engine_script] + args,
        capture_output=False
    )
    sys.exit(result.returncode)

if __name__ == '__main__':
    main()
