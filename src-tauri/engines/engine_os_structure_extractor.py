#!/usr/bin/env python3
"""
ENGINE 2: engine_os_structure_extractor
Raw OS structure extraction using Volatility 3
Input: 01_memory_evidence.json + memory.raw
Output: 02_os_structures.json
"""

import sys
import os
import json
import argparse
import subprocess
import re
from pathlib import Path
from typing import Dict, Any, List

def _find_vol_binary() -> str:
    """Find the bundled vol binary relative to this script, fallback to PATH."""
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        script_dir / "vol",
        script_dir / "vol.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    import shutil
    found = shutil.which("vol")
    return found or "vol"

VOL_BIN = _find_vol_binary()


def load_evidence(evidence_path: Path) -> Dict[str, Any]:
    """Load and validate Engine 1 output"""
    with open(evidence_path, 'r') as f:
        evidence = json.load(f)

    if not evidence.get("validated", False):
        raise ValueError("Engine 1 output not validated")

    if "Windows" not in evidence.get("suspected_os", ""):
        raise ValueError("Windows memory required")

    return evidence


def parse_hex_address(addr_str: str) -> str:
    """Ensure hex address is in 0x format"""
    if not addr_str:
        return "0x0"
    if addr_str.startswith("0x"):
        return addr_str
    return f"0x{addr_str}"


def run_volatility(memory_path: Path, plugin: str, extra_args: List[str] = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """Standardized Volatility runner"""
    cmd = [VOL_BIN, "-f", str(memory_path), plugin]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result


def clean_vol_output(output: str) -> List[str]:
    """Normalize Volatility stdout into clean lines"""
    if not output:
        return []
    output = output.replace('\r', '\n')
    return [line for line in output.split('\n') if line.strip()]


def extract_processes_pslist(memory_path: Path) -> List[Dict[str, Any]]:
    """Extract process list using Volatility 3"""
    print("🔍 Extracting processes via Volatility 3 windows.pslist...")

    result = run_volatility(memory_path, "windows.pslist", timeout=300)

    if result.returncode != 0:
        raise RuntimeError(f"Volatility pslist failed: {result.stderr}")

    processes = []
    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip() or "PID" in line or "---" in line or "Volatility" in line:
            continue

        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            processes.append({
                "pid": int(parts[0]),
                "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                "image_name": parts[2],
                "create_time": " ".join(parts[9:]) if len(parts) > 9 else "1970-01-01 00:00:00",
                "vads": [],
                "threads": []
            })

    return processes


def extract_vads_for_process(memory_path: Path, pid: int) -> List[Dict[str, Any]]:
    """Extract VAD regions for a specific process"""

    result = run_volatility(memory_path, "windows.vadinfo", ["--pid", str(pid)], timeout=60)

    vads = []
    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip() or "PID" in line or "---" in line or "Volatility" in line or "Process" in line:
            continue

        parts = line.split()
        # Columns: PID(0) Process(1) Offset(2) StartVPN(3) EndVPN(4) Tag(5) Protection(6) ...
        if len(parts) >= 7 and parts[0].isdigit():
            try:
                start = int(parts[3], 16)
                end = int(parts[4], 16)
                size = end - start
                protection = parts[6]

                mapped_file = None
                is_private = True

                if len(parts) > 11 and parts[11] != "N/A" and parts[11] != "Disabled":
                    mapped_file = parts[11]
                    is_private = False

                vads.append({
                    "start": parse_hex_address(hex(start)),
                    "end": parse_hex_address(hex(end)),
                    "size": size,
                    "protection": protection,
                    "private": is_private,
                    "mapped_file": mapped_file
                })
            except (ValueError, IndexError):
                continue

    return vads


def extract_all_threads(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract ALL threads at once and organize by PID"""
    print("🧵 Extracting all threads (this may take a moment)...")

    result = run_volatility(memory_path, "windows.threads", timeout=300)

    threads_by_pid = {}
    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["PID", "---", "Volatility", "Progress", "Scanning", "Stacking", "finished", "Offset\t"]):
            continue

        if '\t' in line:
            parts = line.split('\t')
        else:
            parts = line.split()

        if len(parts) < 4:
            continue

        try:
            pid = int(parts[1])
            tid = int(parts[2])
            start_addr = parts[3]
            create_time = parts[7] if len(parts) > 7 and parts[7] != '-' else "N/A"

            if pid not in threads_by_pid:
                threads_by_pid[pid] = []

            threads_by_pid[pid].append({
                "tid": tid,
                "start_address": parse_hex_address(start_addr),
                "create_time": create_time
            })
        except (ValueError, IndexError):
            continue

    return threads_by_pid


def extract_all_cmdlines(memory_path: Path) -> Dict[int, str]:
    """Extract command lines for all processes"""
    print("💻 Extracting command lines via Volatility 3 windows.cmdline...")

    result = run_volatility(memory_path, "windows.cmdline", timeout=300)
    cmdlines_by_pid = {}

    if result.returncode != 0:
        print("⚠️ Command line extraction unavailable")
        return cmdlines_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip() or "PID" in line or "---" in line or "Volatility" in line:
            continue

        match = re.match(r'^\s*(\d+)\s+(\S+)\s+(.*)$', line)
        if match:
            pid = int(match.group(1))
            cmdline = match.group(3).strip()
            if cmdline and cmdline not in ["N/A", "-"]:
                cmdlines_by_pid[pid] = cmdline

    return cmdlines_by_pid


def extract_all_modules(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract loaded modules/DLLs for all processes"""
    print("📦 Extracting loaded modules via Volatility 3 windows.dlllist...")

    result = run_volatility(memory_path, "windows.dlllist", timeout=300)
    modules_by_pid = {}

    if result.returncode != 0:
        print("⚠️ Module extraction unavailable")
        return modules_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["PID", "---", "Volatility", "Base", "Size", "Name", "Path"]):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        pid = None
        for i, part in enumerate(parts):
            if part.isdigit():
                pid = int(part)
                remaining = parts[i + 1:]
                break

        if pid is None or not remaining:
            continue

        path = " ".join(remaining).strip()
        if not path:
            continue

        module_name = Path(path).name if "\\" in path or "/" in path else path

        module = {
            "name": module_name,
            "path": path
        }

        if pid not in modules_by_pid:
            modules_by_pid[pid] = []

        modules_by_pid[pid].append(module)

    return modules_by_pid


# ========== NEW ENGINE 2 ENRICHMENTS (additions, no existing code changed) ==========

def extract_all_user_sids(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract user SIDs for all processes using windows.getsids"""
    print("👤 Extracting user SIDs via Volatility 3 windows.getsids...")

    result = run_volatility(memory_path, "windows.getsids", timeout=300)
    sids_by_pid = {}

    if result.returncode != 0:
        print("⚠️ SID extraction unavailable")
        return sids_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["PID", "---", "Volatility", "Sid", "SID", "Name"]):
            continue

        # Format: PID   SID                                        Name
        #        3692  S-1-5-21-...-4120                           DESKTOP-ABC\Elon
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            try:
                pid = int(parts[0])
                sid = parts[1]
                username = parts[2] if len(parts) > 2 else None

                # Clean username (remove domain prefix like DESKTOP-ABC\Elon → Elon)
                clean_username = None
                if username:
                    if '\\' in username:
                        clean_username = username.split('\\')[-1]
                    else:
                        clean_username = username

                entry = {
                    "sid": sid,
                    "username_full": username,
                    "username": clean_username
                }

                if pid not in sids_by_pid:
                    sids_by_pid[pid] = []
                sids_by_pid[pid].append(entry)
            except (ValueError, IndexError):
                continue

    return sids_by_pid


def extract_all_handles(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract handle tables for all processes, focusing on cross-process handles"""
    print("🔗 Extracting handle tables via Volatility 3 windows.handles...")

    result = run_volatility(memory_path, "windows.handles", timeout=600)  # handles can be slow

    handles_by_pid = {}

    if result.returncode != 0:
        print("⚠️ Handle extraction unavailable")
        return handles_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["PID", "---", "Volatility", "Offset", "Volume"]):
            continue

        parts = line.split()
        if len(parts) < 5 and not parts[0].isdigit():
            continue

        if parts[0].isdigit():
            try:
                pid = int(parts[0])
                handle_type = parts[2] if len(parts) > 2 else None
                granted_access = parts[3] if len(parts) > 3 else None
                name = " ".join(parts[4:]) if len(parts) > 4 else None

                # Only track process and thread handles (cross-process relevance)
                if handle_type in ["Process", "Thread"]:
                    entry = {
                        "type": handle_type,
                        "granted_access": granted_access,
                        "name": name
                    }

                    # Extract target PID from name if it matches "Process(XXXX)" pattern
                    target_pid = None
                    if name:
                        pid_match = re.search(r'\((\d+)\)', name)
                        if pid_match:
                            target_pid = int(pid_match.group(1))
                    
                    if target_pid:
                        entry["target_pid"] = target_pid

                    if pid not in handles_by_pid:
                        handles_by_pid[pid] = []
                    handles_by_pid[pid].append(entry)
            except (ValueError, IndexError):
                continue

    return handles_by_pid


def extract_network_connections(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract network connections from memory using netscan"""
    print("🌐 Extracting network connections via Volatility 3 windows.netscan...")

    result = run_volatility(memory_path, "windows.netscan", timeout=120)
    connections_by_pid = {}

    if result.returncode != 0:
        print("⚠️ Network scan unavailable (try windows.netstat)")
        # Fallback to netstat
        result = run_volatility(memory_path, "windows.netstat", timeout=120)
        if result.returncode != 0:
            print("⚠️ Network extraction unavailable")
            return connections_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["Offset", "Proto", "Local", "---", "Volatility"]):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        if parts[0].isdigit() or not parts[0].isdigit():
            # netscan format: Offset  Proto   LocalAddr      LocalPort  ForeignAddr  ForeignPort  State    PID  Owner
            # Try to find PID in the line
            for i, part in enumerate(parts):
                if part.isdigit() and int(part) > 4:  # PID candidates
                    pid = int(part)
                    # Look for IP:port patterns
                    ip_pattern = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    port_pattern = re.findall(r':(\d{1,5})\b', line)

                    if len(ip_pattern) >= 2 and len(port_pattern) >= 2:
                        entry = {
                            "local_ip": ip_pattern[0],
                            "local_port": int(port_pattern[0]),
                            "remote_ip": ip_pattern[-1],
                            "remote_port": int(port_pattern[-1]),
                            "state": parts[-3] if len(parts) > 5 else "UNKNOWN",
                            "protocol": parts[1] if len(parts) > 1 else "TCP"
                        }

                        if pid not in connections_by_pid:
                            connections_by_pid[pid] = []
                        connections_by_pid[pid].append(entry)
                    break

    return connections_by_pid


def analyze_cmdline_flags(cmdline: str) -> Dict[str, Any]:
    """Analyze command line for suspicious patterns and extract artifacts"""
    flags = {
        "has_hidden_window": False,
        "has_rundll32": False,
        "has_net_use": False,
        "has_unc_path": False,
        "has_remote_dll": False,
        "has_encoded_command": False,
        "extracted_unc_paths": [],
        "extracted_ips": [],
        "suspicious": False
    }

    if not cmdline or cmdline == "N/A":
        return flags

    cmd_lower = cmdline.lower()

    # Hidden window detection
    if "-windowstyle hidden" in cmd_lower or "-w hidden" in cmd_lower:
        flags["has_hidden_window"] = True

    # Proxy execution detection
    if "rundll32" in cmd_lower:
        flags["has_rundll32"] = True

    # Network share detection (net use)
    if "net use" in cmd_lower:
        flags["has_net_use"] = True

    # UNC path detection
    unc_paths = re.findall(r'\\\\[^\s,;]+', cmdline)
    if unc_paths:
        flags["has_unc_path"] = True
        flags["extracted_unc_paths"] = unc_paths

    # Remote DLL execution
    if any(".dll" in p for p in unc_paths):
        flags["has_remote_dll"] = True

    # Encoded command (base64 PowerShell)
    if "-enc" in cmd_lower or "-encodedcommand" in cmd_lower:
        flags["has_encoded_command"] = True

    # IP addresses in command line
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cmdline)
    if ips:
        flags["extracted_ips"] = list(set(ips))

    # Overall suspicious flag
    flags["suspicious"] = any([
        flags["has_hidden_window"],
        flags["has_rundll32"],
        flags["has_remote_dll"],
        flags["has_encoded_command"]
    ])

    return flags


def analyze_module_anomalies(modules: List[Dict[str, Any]], process_name: str) -> List[Dict[str, Any]]:
    """Analyze loaded modules for anomalies"""
    anomalies = []
    module_names = [m["name"].lower() for m in modules]

    # Check for process-specific anomalies
    if process_name in ["lsass.exe", "winlogon.exe"]:
        # These should have specific DLL sets
        pass

    return anomalies


def enrich_process_with_security_context(proc: Dict[str, Any], sids_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Add user SID information to a process"""
    pid = proc["pid"]
    proc["user_sids"] = sids_by_pid.get(pid, [])
    
    # Extract primary username (take first non-builtin username found)
    username = None
    for sid_entry in proc["user_sids"]:
        if sid_entry.get("username"):
            username = sid_entry["username"]
            break
    
    proc["username"] = username


def enrich_process_with_handle_analysis(proc: Dict[str, Any], handles_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Add handle analysis to a process"""
    pid = proc["pid"]
    handles = handles_by_pid.get(pid, [])
    
    openprocess_handles = [h for h in handles if h.get("type") == "Process"]
    thread_handles = [h for h in handles if h.get("type") == "Thread"]
    
    proc["handle_analysis"] = {
        "total_handles": len(handles),
        "openprocess_handles": openprocess_handles,
        "thread_handles": thread_handles,
        "cross_process_handle_count": len(openprocess_handles) + len(thread_handles)
    }


def enrich_process_with_network(proc: Dict[str, Any], connections_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Add network connection information to a process"""
    pid = proc["pid"]
    proc["network_connections"] = connections_by_pid.get(pid, [])


def enrich_process_relationships(processes: List[Dict[str, Any]]) -> None:
    """Add parent image names without modifying existing fields"""
    pid_to_name = {proc["pid"]: proc["image_name"] for proc in processes}

    for proc in processes:
        proc["parent_image_name"] = pid_to_name.get(proc.get("ppid", 0), "UNKNOWN")


def enrich_processes_with_cmdlines(processes: List[Dict[str, Any]], cmdlines_by_pid: Dict[int, str]) -> None:
    """Add command lines to process records"""
    for proc in processes:
        pid = proc["pid"]
        cmdline = cmdlines_by_pid.get(pid, "N/A")
        proc["command_line"] = cmdline
        # NEW: Analyze command line flags
        proc["cmdline_analysis"] = analyze_cmdline_flags(cmdline)


def enrich_processes_with_modules(processes: List[Dict[str, Any]], modules_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Add module lists to process records"""
    for proc in processes:
        modules = modules_by_pid.get(proc["pid"], [])
        proc["modules"] = modules
        # NEW: Check for anomalies
        proc["module_anomalies"] = analyze_module_anomalies(modules, proc["image_name"])


def add_enrichment_status(processes: List[Dict[str, Any]], cmdlines_by_pid: Dict[int, str], modules_by_pid: Dict[int, List[Dict[str, Any]]], threads_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Track which enrichments were available per process"""
    for proc in processes:
        pid = proc["pid"]
        proc["enrichment_status"] = {
            "threads": "ok" if pid in threads_by_pid else "missing",
            "cmdline": "ok" if pid in cmdlines_by_pid else "missing",
            "modules": "ok" if pid in modules_by_pid else "missing",
            "parent_image_name": "ok" if proc.get("parent_image_name") not in [None, "", "UNKNOWN"] else "missing",
            # NEW enrichments
            "user_sids": "ok" if proc.get("user_sids") else "missing",
            "handles": "ok" if proc.get("handle_analysis") and proc["handle_analysis"]["total_handles"] > 0 else "missing",
            "network": "ok" if proc.get("network_connections") else "missing"
        }


def validate_structures(structures: Dict[str, Any]) -> bool:
    """Strict validation of extracted structures"""
    processes = structures.get("processes", [])
    if not processes:
        return False

    for proc in processes:
        if proc.get("pid", 0) <= 0:
            return False
        if not proc.get("image_name"):
            return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Engine 2: OS Structure Extractor")
    parser.add_argument("evidence_json", help="01_memory_evidence.json")
    parser.add_argument("memory_file", help="memory.raw")
    parser.add_argument("--output", default="02_os_structures.json")
    parser.add_argument("--limit", type=int, default=10,
                        help="Limit processes for demo (0=all)")

    args = parser.parse_args()

    evidence_path = Path(args.evidence_json)
    memory_path = Path(args.memory_file)
    output_path = Path(args.output)

    try:
        print("🚀 ENGINE 2: Starting OS structure extraction...")

        # Input validation
        evidence = load_evidence(evidence_path)
        print(f"📄 Evidence validated: {evidence['image_sha256'][:16]}...")

        # Extract processes
        processes = extract_processes_pslist(memory_path)

        if not processes:
            raise ValueError("No processes extracted")

        print(f"📊 Found {len(processes)} processes")

        # Extract ALL threads at once (efficient)
        threads_by_pid = extract_all_threads(memory_path)
        print(f"✓ Extracted threads for {len(threads_by_pid)} processes")

        # Existing enrichments: command lines and modules
        cmdlines_by_pid = extract_all_cmdlines(memory_path)
        print(f"✓ Extracted command lines for {len(cmdlines_by_pid)} processes")

        modules_by_pid = extract_all_modules(memory_path)
        print(f"✓ Extracted module lists for {len(modules_by_pid)} processes")

        # ========== NEW ENRICHMENTS ==========
        # User SIDs (who ran each process)
        sids_by_pid = extract_all_user_sids(memory_path)
        print(f"✓ Extracted SIDs for {len(sids_by_pid)} processes")

        # Handle tables (cross-process artifact tracking)
        handles_by_pid = extract_all_handles(memory_path)
        print(f"✓ Extracted handles for {len(handles_by_pid)} processes")

        # Network connections
        connections_by_pid = extract_network_connections(memory_path)
        print(f"✓ Extracted network connections for {len(connections_by_pid)} processes")

        # Add parent image names
        enrich_process_relationships(processes)

        # Add command lines and module info (with cmdline analysis)
        enrich_processes_with_cmdlines(processes, cmdlines_by_pid)
        enrich_processes_with_modules(processes, modules_by_pid)

        # NEW: Enrich with security context, handles, and network
        for proc in processes:
            pid = proc["pid"]
            enrich_process_with_security_context(proc, sids_by_pid)
            enrich_process_with_handle_analysis(proc, handles_by_pid)
            enrich_process_with_network(proc, connections_by_pid)

        # Extract VADs and assign threads
        process_limit = args.limit if args.limit > 0 else len(processes)
        for proc in processes[:process_limit]:
            pid = proc["pid"]

            try:
                print(f" 📊 Extracting VADs for PID {pid}...", end='')
                proc["vads"] = extract_vads_for_process(memory_path, pid)
                proc["threads"] = threads_by_pid.get(pid, [])
                print(f" {len(proc['vads'])} VADs, {len(proc['threads'])} threads")
            except Exception as e:
                print(f" ⚠️ Error: {e}")
                if "vads" not in proc:
                    proc["vads"] = []
                if "threads" not in proc:
                    proc["threads"] = []

        # Add enrichment status without changing existing structure
        add_enrichment_status(processes, cmdlines_by_pid, modules_by_pid, threads_by_pid)

        structures = {
            "engine_id": "engine_os_structure_extractor",
            "processes": processes
        }

        # Output validation
        if not validate_structures(structures):
            raise ValueError("OS structures validation failed")

        # Save output
        with open(output_path, 'w') as f:
            json.dump(structures, f, indent=2)

        print("✅ ENGINE 2 COMPLETE")
        print(f"📊 Processes: {len(structures['processes'])}")
        total_vads = sum(len(p.get('vads', [])) for p in processes)
        total_threads = sum(len(p.get('threads', [])) for p in processes)
        total_cmdlines = sum(1 for p in processes if p.get('command_line', 'N/A') != 'N/A')
        total_modules = sum(len(p.get('modules', [])) for p in processes)
        total_sids = sum(1 for p in processes if p.get('user_sids'))
        total_handles = sum(1 for p in processes if p.get('handle_analysis'))
        total_networks = sum(1 for p in processes if p.get('network_connections'))
        print(f"📊 Total VADs: {total_vads}")
        print(f"📊 Total Threads: {total_threads}")
        print(f"📊 Total Command Lines: {total_cmdlines}")
        print(f"📊 Total Modules: {total_modules}")
        print(f"📊 Total with SIDs: {total_sids}")
        print(f"📊 Total with Handles: {total_handles}")
        print(f"📊 Total with Network: {total_networks}")
        print(f"📄 Output: {output_path.absolute()}")

    except Exception as e:
        print(f"❌ ENGINE 2 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
