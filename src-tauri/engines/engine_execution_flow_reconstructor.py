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
    with open(evidence_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    events = data.get("execution_events", [])
    if len(events) == 0:
        # Zero proven executions is a legitimate result (e.g. resident-memory-only
        # malware with no thread-start/VAD overlap), not a failure. Aborting here
        # left a STALE 05_execution_timeline.json on disk from a prior run, which
        # E6 then silently loaded as if it were current. Always write a fresh,
        # empty-but-current timeline instead.
        print("⚠️  No execution evidence found — writing empty (but current) timeline", file=sys.stderr)

    return events


def load_os_structures(os_structures_path: Path) -> Dict[str, Any]:
    """Load Engine 2 output for enrichment data (cmdlines, users, handles)"""
    with open(os_structures_path, 'r', encoding='utf-8') as f:
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
        else:
            # Default role for events with unknown PIDs
            if "execution_role" not in event:
                event["execution_role"] = "unknown"
    
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

    # High cross-process handle count on a process (Process/Thread handles into
    # other PIDs) is the actual signal for an injection source — not a fixed
    # PID allowlist, which would never fire on any dump other than the one
    # this threshold was originally tuned against.
    handles = pid_data.get("handle_analysis", {})
    if handles.get("cross_process_handle_count", 0) > 10:
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


def detect_bursts(timeline: List[Dict[str, Any]], window_seconds: float = 0.2,
                   min_burst_size: int = 3) -> Dict[str, Any]:
    """
    Flag temporal bursts: N+ events on the same PID within a short window.
    A pile of thread creations on one process in a fraction of a second is a
    strong injection signal almost never seen in normal process behavior.
    """
    by_pid: Dict[int, List[Dict[str, Any]]] = {}
    for event in timeline:
        pid = event.get("pid")
        by_pid.setdefault(pid, []).append(event)

    bursts = []
    for pid, events in by_pid.items():
        times = sorted(parse_timestamp(e.get("create_time", "")) for e in events)
        if len(times) < min_burst_size:
            continue
        i = 0
        while i < len(times):
            j = i
            while j + 1 < len(times) and times[j + 1] - times[i] <= window_seconds:
                j += 1
            cluster_size = j - i + 1
            if cluster_size >= min_burst_size:
                bursts.append({
                    "pid": pid,
                    "event_count": cluster_size,
                    "window_seconds": window_seconds,
                    "start_time": times[i],
                    "end_time": times[j],
                })
            i = j + 1

    for event in timeline:
        event["burst_flagged"] = False
    for b in bursts:
        for event in timeline:
            if event.get("pid") == b["pid"]:
                t = parse_timestamp(event.get("create_time", ""))
                if b["start_time"] <= t <= b["end_time"]:
                    event["burst_flagged"] = True

    return {"bursts_detected": len(bursts), "bursts": bursts}


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

        # NEW: Merge process creation events from OS structures into timeline
        if args.os_structures:
            os_path = Path(args.os_structures)
            if os_path.exists():
                print("  🔄 Enriching timeline with OS structure data...")
                os_data = load_os_structures(os_path)
                pid_lookup = build_pid_lookup(os_data)
                events = enrich_timeline_events(events, pid_lookup)

                # Merge process creation/exit events into timeline
                print("  🔄 Merging process creation events into timeline...")
                pid_set = set(p.get("pid") for p in os_data.get("processes", []))
                for proc in os_data.get("processes", []):
                    proc_event = {
                        "event_type": "process_creation",
                        "pid": proc.get("pid"),
                        "process_image": proc.get("image_name", "Unknown"),
                        "create_time": proc.get("create_time", ""),
                        "ppid": proc.get("ppid"),
                        "parent_process": proc.get("parent_image_name", "UNKNOWN"),
                        "command_line": proc.get("command_line", "N/A"),
                        "username": proc.get("username", ""),
                        "execution_role": "process_lifecycle",
                    }
                    # Orphan detection
                    ppid = proc.get("ppid", 0)
                    if ppid and ppid not in pid_set:
                        proc_event["orphan_parent"] = True
                        proc_event["orphan_note"] = f"Parent PID {ppid} not in process list (exited before capture)"
                    events.append(proc_event)
                print(f"  ✓ Added {len(os_data.get('processes', []))} process creation events")

        print(f"📊 Sorting {len(events)} execution events...")

        timeline = reconstruct_timeline(events)

        burst_analysis = detect_bursts(timeline)
        print(f"💥 Burst analysis: {burst_analysis['bursts_detected']} burst(s) detected")

        output = {
            "engine_id": "engine_execution_flow_reconstructor",
            "execution_timeline": timeline,
            "timeline_length": len(timeline),
            "sort_criteria": "thread_create_time (primary), allocation_sequence (secondary)",
            "burst_analysis": burst_analysis,
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
