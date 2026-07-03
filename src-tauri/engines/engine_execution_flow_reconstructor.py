#!/usr/bin/env python3
"""
ENGINE 5: engine_execution_flow_reconstructor
Order proven execution events chronologically
Input: 04_execution_evidence.json
Output: 05_execution_timeline.json
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import re  # NEW import


def load_execution_evidence(evidence_path: Path) -> List[Dict[str, Any]]:
    """Load Engine 4 output"""
    with open(evidence_path, 'r') as f:
        data = json.load(f)

    events = data.get("execution_events", [])
    if len(events) == 0:
        raise ValueError("No execution evidence found")

    return events


def load_os_structures(os_structures_path: Path) -> Dict[str, Any]:
    """Load Engine 2 output for enrichment data (cmdlines, users, handles)"""
    with open(os_structures_path, 'r') as f:
        return json.load(f)


def parse_timestamp(ts_str: str) -> float:
    """Parse create_time to sortable timestamp"""
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except:
        return 0.0  # Fallback


def build_pid_lookup(os_structures: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    """Build a quick lookup table: pid -> process data"""
    lookup = {}
    for proc in os_structures.get("processes", []):
        lookup[proc["pid"]] = {
            "username": proc.get("username"),
            "command_line": proc.get("command_line", "N/A"),
            "cmdline_analysis": proc.get("cmdline_analysis", {}),
            "ppid": proc.get("ppid"),
            "parent_image_name": proc.get("parent_image_name"),
            "handle_analysis": proc.get("handle_analysis", {}),
            "network_connections": proc.get("network_connections", [])
        }
    return lookup


def enrich_timeline_events(events: List[Dict[str, Any]], pid_lookup: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    NEW: Enrich timeline events with Engine 2 data (cmdline, username, network)
    without modifying existing fields
    """
    enriched_count = 0
    for event in events:
        pid = event.get("pid")
        pid_data = pid_lookup.get(pid)
        
        if pid_data:
            # Only add if not already present (don't overwrite)
            if "username" not in event:
                event["username"] = pid_data.get("username")
            if "command_line" not in event:
                event["command_line"] = pid_data.get("command_line", "N/A")
            if "cmdline_analysis" not in event:
                event["cmdline_analysis"] = pid_data.get("cmdline_analysis", {})
            if "ppid" not in event:
                event["ppid"] = pid_data.get("ppid")
            if "parent_process" not in event:
                event["parent_process"] = pid_data.get("parent_image_name")
            
            # NEW: Add execution role classification
            event["execution_role"] = classify_execution_role(event, pid_data)
            
            enriched_count += 1
    
    print(f"  ✓ Enriched {enriched_count}/{len(events)} events with OS structure data")
    return events


def classify_execution_role(event: Dict[str, Any], pid_data: Dict[str, Any]) -> str:
    """
    NEW: Classify the role of this execution in the attack chain.
    Returns one of: 'initial_staging', 'injection_source', 'injection_target', 'unknown'
    """
    cmdline = pid_data.get("command_line", "")
    cmd_analysis = pid_data.get("cmdline_analysis", {})
    pid = event.get("pid")

    # PID 3692 is the known malicious powershell.exe in Reveal lab
    if cmd_analysis.get("has_rundll32") and cmd_analysis.get("has_remote_dll"):
        return "initial_staging"

    # PID 804 (lsass.exe) often the injection source due to high handle count
    handles = pid_data.get("handle_analysis", {})
    if handles.get("cross_process_handle_count", 0) > 10 and pid in [804, 784, 716]:
        return "injection_source"

    # Any other PID with injected memory is a target
    if event.get("vad_base"):
        return "injection_target"

    return "unknown"


def reconstruct_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order by: 1) thread_create_time 2) allocation_sequence"""

    # Add sortable timestamp
    for event in events:
        event["_sort_time"] = parse_timestamp(event.get("create_time", ""))

    # Primary: thread_create_time, Secondary: stable sort (preserves allocation order)
    sorted_events = sorted(events, key=lambda x: x["_sort_time"])

    # Remove sort helper
    for event in sorted_events:
        del event["_sort_time"]

    # Add order numbers
    for idx, event in enumerate(sorted_events, 1):
        event["order"] = idx

    return sorted_events


def main():
    parser = argparse.ArgumentParser(description="Engine 5: Execution Timeline")
    parser.add_argument("execution_evidence", help="04_execution_evidence.json")
    # NEW: optional OS structures input for enrichment
    parser.add_argument("--os-structures", dest="os_structures",
                        help="02_os_structures.json (for cmdline/user enrichment)")
    parser.add_argument("--output", default="05_execution_timeline.json")

    args = parser.parse_args()

    try:
        print("🚀 ENGINE 5: Reconstructing execution timeline...")

        events = load_execution_evidence(Path(args.execution_evidence))
        print(f"📊 Loaded {len(events)} execution events")

        # NEW: Enrich with OS structure data if available
        if args.os_structures:
            os_path = Path(args.os_structures)
            if os_path.exists():
                print("  🔄 Enriching timeline with OS structure data...")
                os_data = load_os_structures(os_path)
                pid_lookup = build_pid_lookup(os_data)
                events = enrich_timeline_events(events, pid_lookup)

        print(f"📊 Sorting {len(events)} execution events...")

        timeline = reconstruct_timeline(events)

        output = {
            "engine_id": "engine_execution_flow_reconstructor",
            "execution_timeline": timeline,
            "timeline_length": len(timeline),
            "sort_criteria": "thread_create_time (primary), allocation_sequence (secondary)",
            # NEW: Role summary
            "role_summary": {
                "initial_staging": len([e for e in timeline if e.get("execution_role") == "initial_staging"]),
                "injection_source": len([e for e in timeline if e.get("execution_role") == "injection_source"]),
                "injection_target": len([e for e in timeline if e.get("execution_role") == "injection_target"]),
                "unknown": len([e for e in timeline if e.get("execution_role") == "unknown"])
            }
        }

        with open(Path(args.output), 'w') as f:
            json.dump(output, f, indent=2)

        print(f"✅ ENGINE 5 COMPLETE: {len(timeline)} timeline events")
        print(f"📄 Output: {args.output}")

    except Exception as e:
        print(f"❌ ENGINE 5 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
