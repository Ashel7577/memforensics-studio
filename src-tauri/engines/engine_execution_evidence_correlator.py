#!/usr/bin/env python3
"""
ENGINE 4: engine_execution_evidence_correlator (CORE)
Forensic Proof of Execution - ThreadStart ∈ VADRegion
Input: 02_os_structures.json + 03_private_exec_regions.json
Output: 04_execution_evidence.json
STRICT: No heuristics. Math only.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict
import re

def load_inputs(os_structures_path: Path, exec_regions_path: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Load and validate inputs"""
    with open(os_structures_path, 'r', encoding='utf-8') as f:
        os_structures = json.load(f)
    
    with open(exec_regions_path, 'r', encoding='utf-8') as f:
        exec_regions = json.load(f)
    
    if len(os_structures.get("processes", [])) == 0:
        raise ValueError("No processes in OS structures")
    
    if len(exec_regions.get("private_exec_regions", [])) == 0:
        print("⚠️ No private exec regions found", file=sys.stderr)
    
    return os_structures, exec_regions

def parse_address(addr_str: str) -> int:
    """Convert hex address string to integer"""
    if isinstance(addr_str, str):
        addr_str = addr_str.replace("0x", "").lower()
        return int(addr_str, 16)
    return int(addr_str)

def thread_executes_in_region(thread_start: str, region_base: int, region_size: int) -> bool:
    """
    STRICT MATHEMATICAL VALIDATION:
    thread_start_address ∈ [region_base, region_base + region_size)
    """
    thread_addr = parse_address(thread_start)
    region_end = region_base + region_size
    
    return region_base <= thread_addr < region_end

PROCESS_VM_WRITE = 0x20
PROCESS_CREATE_THREAD = 0x2
PROCESS_VM_OPERATION = 0x8
PROCESS_ALL_ACCESS = 0x1FFFFF


def _handle_capable(access) -> bool:
    """FIX E4-1: Volatility 3 emits GrantedAccess as a hex bitmask (e.g.
    '0x1FFFFF'), not a symbolic name — the old substring test could never
    match, so the injection graph was always empty. Accept raw hex masks
    and Engine 2 symbolic names.
    """
    if access is None:
        return False
    s = str(access)
    for name in ("VM_WRITE", "CREATE_THREAD", "ALL_ACCESS", "VM_OPERATION"):
        if name in s.upper():
            return True
    try:
        mask = int(s, 16)
    except ValueError:
        return False
    return bool(mask & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD |
                        PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS))


def build_injection_graph(os_structures: Dict[str, Any]) -> Dict[str, Any]:
    """
    Walk each process's handle table (from Engine 2) and build a directed
    graph: source_pid -> target_pid wherever source holds a process/thread
    handle to target with write/create-thread-capable access rights. The PID
    with edges out to many targets and none in is the likely injection source.
    """
    edges = []
    out_degree = defaultdict(int)
    in_degree = defaultdict(int)

    for proc in os_structures.get("processes", []):
        source_pid = proc.get("pid")
        handle_analysis = proc.get("handle_analysis", {})
        candidate_handles = (handle_analysis.get("openprocess_handles", []) +
                             handle_analysis.get("thread_handles", []))
        for h in candidate_handles:
            target_pid = h.get("target_pid")
            access = h.get("granted_access")
            if not target_pid or target_pid == source_pid:
                continue
            if _handle_capable(access):
                edges.append({
                    "source_pid": source_pid,
                    "target_pid": target_pid,
                    "access": access,
                    "handle_type": h.get("type"),
                })
                out_degree[source_pid] += 1
                in_degree[target_pid] += 1

    root_source_pid = None
    if out_degree:
        # Root source: highest out-degree with zero in-degree (nothing injects into it)
        candidates = [(pid, deg) for pid, deg in out_degree.items() if in_degree.get(pid, 0) == 0]
        pool = candidates if candidates else list(out_degree.items())
        root_source_pid = max(pool, key=lambda kv: kv[1])[0]

    root_process = None
    if root_source_pid is not None:
        match = next((p for p in os_structures.get("processes", []) if p.get("pid") == root_source_pid), None)
        root_process = match.get("image_name") if match else None

    return {
        "edges": edges,
        "root_source_pid": root_source_pid,
        "root_source_process": root_process,
        "total_edges": len(edges),
    }


def correlate_execution(os_structures: Dict[str, Any], exec_regions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Core correlation engine - PROOF OF EXECUTION ONLY"""
    execution_evidence = []
    
    # Group regions by PID (multiple regions per PID)
    region_dict = defaultdict(list)
    for r in exec_regions["private_exec_regions"]:
        region_dict[r["pid"]].append(r)
    
    print("🔍 Correlating thread starts → private exec regions...")
    
    for proc in os_structures["processes"]:
        pid = proc["pid"]
        threads = proc.get("threads", [])
        
        if pid not in region_dict:
            continue
            
        regions_for_pid = region_dict[pid]
        for thread in threads:
            thread_start = thread.get("start_address")
            thread_id = thread.get("tid")
            create_time = thread.get("create_time")
            if thread_start is None:
                continue  # FIX E4-2: missing/malformed thread — skip, never abort the run
            
            for region in regions_for_pid:
                region_base = parse_address(region["base_address"])
                region_size = region.get("size", 0)
                if isinstance(region_size, str):
                    try:
                        region_size = int(region_size, 0)  # FIX E4-4: auto-detect 0x / decimal
                    except ValueError:
                        region_size = 0
                
                if thread_executes_in_region(thread_start, region_base, region_size):
                    # ✅ PROOF OF EXECUTION FOUND
                    thread_addr = parse_address(thread_start)
                    
                    evidence = {
                        "pid": pid,
                        "thread_id": thread_id,
                        "process_image": proc.get("image_name", "Unknown"),
                        "thread_start_address": thread_start,
                        "create_time": create_time,
                        "exec_region": {
                            "base_address": region["base_address"],
                            "size": region["size"],
                            "permissions": region["permissions"],
                            "region_analysis": region.get("region_analysis", {}),
                        },
                        "proof_method": "ThreadStart ∈ VADRegion",
                        "overlap_start": hex(max(thread_addr, region_base)),
                        "overlap_end": hex(min(thread_addr + 1, region_base + region_size))
                    }
                    execution_evidence.append(evidence)
                    print(f"✅ EXECUTION PROVEN: PID {pid} Thread {thread_id}")
    
    return execution_evidence

def validate_timestamps(evidence: List[Dict[str, Any]], os_structures: Dict[str, Any]) -> bool:
    """Validate thread create_time ≥ process create_time"""
    for item in evidence:
        pid = item["pid"]
        proc = next((p for p in os_structures["processes"] if p["pid"] == pid), None)
        if not proc:
            return False
        t_thread = str(item.get("create_time") or "").strip()
        t_proc = str(proc.get("create_time") or "").strip()
        if t_thread and t_proc and t_thread < t_proc:
            return False  # FIX E4-3: thread cannot predate its own process
    return True


def correlate_network(os_structures: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlate processes with their network connections to identify C2 traffic."""
    events = []
    for proc in os_structures.get("processes", []):
        pid = proc.get("pid")
        connections = proc.get("network_connections", [])
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            if not remote_ip or remote_ip in ("0.0.0.0", "*", "::"):
                continue
            events.append({
                "pid": pid,
                "process_image": proc.get("image_name", "Unknown"),
                "create_time": proc.get("create_time", ""),
                "proof_method": "network_connection",
                "network_detail": {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_ip": conn.get("local_ip", ""),
                    "local_port": conn.get("local_port", 0),
                    "protocol": conn.get("protocol", ""),
                    "state": conn.get("state", ""),
                },
            })
    return events


def correlate_file_handles(os_structures: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlate processes with file handle access to forensically interesting paths."""
    events = []
    INTERESTING_PATTERNS = [
        "Login Data", "Cookies", "Web Data", "History", "Bookmarks",
        "User Data", "Chrome", "Edge", "Firefox",
        ".zip", ".rar", ".7z",
        "\\Temp\\", "\\Tmp\\",
        ".png", ".jpg", ".bmp",
        "wallet.dat", "electrum", "exodus",
    ]
    for proc in os_structures.get("processes", []):
        pid = proc.get("pid")
        handle_analysis = proc.get("handle_analysis", {})
        file_handles = handle_analysis.get("file_handles", [])
        for h in file_handles:
            name = h.get("name", "") or ""
            if any(pat.lower() in name.lower() for pat in INTERESTING_PATTERNS):
                events.append({
                    "pid": pid,
                    "process_image": proc.get("image_name", "Unknown"),
                    "create_time": proc.get("create_time", ""),
                    "proof_method": "file_handle_access",
                    "file_detail": {
                        "file_path": name,
                        "handle_type": h.get("type", ""),
                        "granted_access": h.get("granted_access", ""),
                    },
                })
    return events


def correlate_registry_handles(os_structures: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlate processes with registry key access for persistence detection."""
    events = []
    PERSISTENCE_KEYS = [
        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
        "CurrentVersion\\RunServices", "Policies\\Explorer\\Run",
        "CurrentVersion\\Explorer\\Shell Folders",
    ]
    for proc in os_structures.get("processes", []):
        pid = proc.get("pid")
        handle_analysis = proc.get("handle_analysis", {})
        registry_handles = handle_analysis.get("registry_handles", [])
        for h in registry_handles:
            name = h.get("name", "") or ""
            if any(pk.lower() in name.lower() for pk in PERSISTENCE_KEYS):
                events.append({
                    "pid": pid,
                    "process_image": proc.get("image_name", "Unknown"),
                    "create_time": proc.get("create_time", ""),
                    "proof_method": "registry_handle_access",
                    "registry_detail": {
                        "key_path": name,
                        "handle_type": h.get("type", ""),
                        "granted_access": h.get("granted_access", ""),
                    },
                })
    return events


def main():
    parser = argparse.ArgumentParser(description="Engine 4: Execution Correlator (CORE)")
    parser.add_argument("os_structures", help="02_os_structures.json")
    parser.add_argument("private_exec_regions", help="03_private_exec_regions.json")
    parser.add_argument("--output", default="04_execution_evidence.json")
    
    args = parser.parse_args()
    
    try:
        print("🚀 ENGINE 4: CORE EXECUTION CORRELATOR")
        print("⚠️  EXECUTION PROOF REQUIRES: $ThreadStart ∈ VADRegion")
        
        # Load inputs
        os_structures, exec_regions = load_inputs(
            Path(args.os_structures), 
            Path(args.private_exec_regions)
        )
        
        # Generate proof
        execution_evidence = correlate_execution(os_structures, exec_regions)

        # Injection graph (additive) — built independently of exec correlation
        injection_graph = build_injection_graph(os_structures)
        print(f"🔗 Injection graph: {injection_graph['total_edges']} cross-process handle edge(s), "
              f"root source PID: {injection_graph['root_source_pid']}")
        
        # Timestamp validation
        if not validate_timestamps(execution_evidence, os_structures):
            raise ValueError("Timestamp validation failed")
        
        # Correlate network connections, file handles, and registry access
        network_events = correlate_network(os_structures)
        file_events = correlate_file_handles(os_structures)
        registry_events = correlate_registry_handles(os_structures)
        print(f"🌐 Network correlations: {len(network_events)} events")
        print(f"📁 File handle correlations: {len(file_events)} events")
        print(f"📝 Registry correlations: {len(registry_events)} events")

        # Combine all evidence
        all_evidence = execution_evidence + network_events + file_events + registry_events
        
        output = {
            "engine_id": "engine_execution_evidence_correlator",
            "execution_events": all_evidence,
            "total_proven_executions": len(execution_evidence),
            "total_network_correlations": len(network_events),
            "total_file_correlations": len(file_events),
            "total_registry_correlations": len(registry_events),
            "correlation_method": "ThreadStart ∈ PrivateExecVAD + handle/network correlation",
            "injection_graph": injection_graph
        }
        
        # Final validation - NO EXECUTION WITHOUT PROOF
        if len(all_evidence) > 0:
            with open(Path(args.output), 'w') as f:
                json.dump(output, f, indent=2)
            print(f"✅ ENGINE 4 COMPLETE: {len(execution_evidence)} proven executions, "
                  f"{len(network_events)} network, {len(file_events)} file, {len(registry_events)} registry")
        else:
            print("⚠️  No execution evidence found")
            output["execution_events"] = []
            with open(Path(args.output), 'w') as f:
                json.dump(output, f, indent=2)
        
        print(f"📄 Output: {args.output}")
        
    except Exception as e:
        print(f"❌ ENGINE 4 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()