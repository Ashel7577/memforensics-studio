#!/usr/bin/env python3
"""
ENGINE 3: engine_private_exec_memory_analyzer
Filter for private executable memory regions
Input: 02_os_structures.json
Output: 03_private_exec_regions.json
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, List

def load_os_structures(structures_path: Path) -> Dict[str, Any]:
    """Load and validate Engine 2 output"""
    with open(structures_path, 'r') as f:
        structures = json.load(f)
    
    processes = structures.get("processes", [])
    if not processes:
        raise ValueError("No processes found in OS structures")
    
    return structures

def is_private_exec_region(vad: Dict[str, Any]) -> bool:
    """Strict filtering rules for private executable regions"""
    # ALL conditions must pass
    protection = vad.get("protection", "").upper()
    private = vad.get("private", False)
    mapped_file = vad.get("mapped_file")
    size = vad["size"]
    
    # Rule A: Must have EXECUTE permission
    if "EXECUTE" not in protection:
        return False
    
    # Rule B: Must be private/anonymous
    if not private:
        return False
    
    # Rule C: No mapped file
    if mapped_file is not None:
        return False
    
    # Rule D: Size between 4KB and 256MB
    if not (4096 <= size <= 256 * 1024 * 1024):
        return False
    
    # Explicit exclusions
    excluded_protections = [
        "GUARD", "JIT", "CLR", "WOW64"
    ]
    for excl in excluded_protections:
        if excl in protection:
            return False
    
    return True

def analyze_regions(structures: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract only valid private executable regions"""
    private_exec_regions = []
    
    for proc in structures["processes"]:
        pid = proc["pid"]
        vads = proc.get("vads", [])
        
        for i, vad in enumerate(vads):
            if is_private_exec_region(vad):
                region = {
                    "pid": pid,
                    "process_image": proc.get("image_name", "Unknown"),
                    "base_address": vad["start"],
                    "size": vad["size"],
                    "permissions": vad["protection"],
                    "vad_index": i,
                    "vad_type": vad.get("tag", vad.get("type", "Private"))
                }
                private_exec_regions.append(region)
    
    return private_exec_regions

def main():
    parser = argparse.ArgumentParser(description="Engine 3: Private Exec Analyzer")
    parser.add_argument("os_structures", help="02_os_structures.json")
    parser.add_argument("--output", default="03_private_exec_regions.json")
    
    args = parser.parse_args()
    
    structures_path = Path(args.os_structures)
    output_path = Path(args.output)
    
    try:
        print("🚀 ENGINE 3: Analyzing private executable regions...")
        
        # Input validation
        structures = load_os_structures(structures_path)
        print(f"📊 Analyzing {len(structures['processes'])} processes...")
        
        # Filter regions
        regions = analyze_regions(structures)
        
        output = {
            "engine_id": "engine_private_exec_memory_analyzer",
            "total_regions_scanned": sum(len(p.get("vads", [])) for p in structures["processes"]),
            "private_exec_regions": regions,
            "region_count": len(regions)
        }
        
        # Output validation
        if len(regions) == 0:
            print("⚠️  No private executable regions found")
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ ENGINE 3 COMPLETE")
        print(f"🎯 Private exec regions: {len(regions)}")
        print(f"📄 Output: {output_path.absolute()}")
        
    except Exception as e:
        print(f"❌ ENGINE 3 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

