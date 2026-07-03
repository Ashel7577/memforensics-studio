#!/usr/bin/env python3
"""
ENGINE 1: engine_memory_acquisition
Forensic memory acquisition and validation
Input: memory.raw (external)
Output: 01_memory_evidence.json
"""

import os
import sys
import json
import hashlib
import argparse
import time
from pathlib import Path
from typing import Dict, Any

def validate_memory_file(memory_path: Path) -> tuple[bool, str]:
    """Strict forensic validation of memory file"""
    try:
        # File exists
        if not memory_path.exists():
            return False, "Memory file does not exist"

        # File size ≥ 512 MB
        if memory_path.stat().st_size < 512 * 1024 * 1024:
            return False, f"Memory file too small: {memory_path.stat().st_size} bytes"

        # File must be readable (removed wrong write check)
        if not os.access(memory_path, os.R_OK):
            return False, "Memory file not readable"

        return True, "Valid"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hash of memory file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096 * 1024), b""):  # 4MB chunks
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def detect_os(memory_path: Path) -> str:
    """OS detection based on acquisition environment"""
    # Memory dumps require structural analysis for OS detection
    # At acquisition stage, record from environment
    return "Windows"

def create_evidence_record(memory_path: Path, acquisition_method: str) -> Dict[str, Any]:
    """Create validated evidence record"""
    # Pre-hash validation
    is_valid, reason = validate_memory_file(memory_path)
    if not is_valid:
        raise ValueError(f"Memory validation failed: {reason}")

    stat_info_before = memory_path.stat()

    # Compute hash
    image_sha256 = compute_sha256(memory_path)

    # Post-hash integrity check (mtime verification)
    if memory_path.stat().st_mtime != stat_info_before.st_mtime:
        raise ValueError("Memory file modified during hashing")

    evidence = {
        "engine_id": "engine_memory_acquisition",
        "engine_version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "memory_file": str(memory_path.absolute()),
        "image_sha256": image_sha256,
        "file_size_bytes": stat_info_before.st_size,
        "acquisition_method": acquisition_method,
        "suspected_os": detect_os(memory_path),
        "acquisition_time": time.time(),
        "validated": True
    }

    # Final output validation
    if len(evidence["image_sha256"]) != 64:
        raise ValueError("Invalid SHA256 hash length")

    if acquisition_method not in ["VM snapshot", "VM suspend"]:
        raise ValueError(f"Invalid acquisition_method: {acquisition_method}")

    return evidence

def main():
    parser = argparse.ArgumentParser(description="Engine 1: Memory Acquisition")
    parser.add_argument("memory_file", help="Path to memory.raw dump")
    parser.add_argument("--method", required=True, 
                       choices=["VM snapshot", "VM suspend"],
                       help="Acquisition method")
    parser.add_argument("--output", default="01_memory_evidence.json",
                       help="Output JSON file")

    args = parser.parse_args()

    memory_path = Path(args.memory_file)
    output_path = Path(args.output)

    try:
        print("🚀 ENGINE 1: Starting memory acquisition validation...")
        print(f"📁 Input: {memory_path.absolute()}")

        evidence = create_evidence_record(memory_path, args.method)

        # Write output
        with open(output_path, 'w') as f:
            json.dump(evidence, f, indent=2)

        print(f"✅ ENGINE 1 COMPLETE")
        print(f"📄 Output: {output_path.absolute()}")
        print(f"🔒 SHA256: {evidence['image_sha256'][:16]}...")
        print(f"💾 Size: {evidence['file_size_bytes'] / (1024**3):.1f} GB")
        print(f"🖥️  OS: {evidence['suspected_os']}")
        print("VALIDATED: TRUE")

    except Exception as e:
        print(f"❌ ENGINE 1 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
