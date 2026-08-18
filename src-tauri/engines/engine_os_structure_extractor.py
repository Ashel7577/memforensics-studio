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
import math
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional


def load_evidence(evidence_path: Path) -> Dict[str, Any]:
    """Load and validate Engine 1 output"""
    with open(evidence_path, 'r', encoding='utf-8') as f:
        evidence = json.load(f)

    if not evidence.get("validated", False):
        raise ValueError("Engine 1 output not validated")

    if "Windows" not in evidence.get("suspected_os", ""):
        raise ValueError("Windows memory required")

    return evidence


def _find_vol_binary() -> str:
    """Locate the Volatility executable.

    The app ships a standalone `vol` next to the engines so it works on a
    machine with nothing installed. Order of preference:

      1. alongside the running executable — when these engines are frozen by
         PyInstaller, ``__file__`` points inside the extracted temp directory,
         so the bundled binary has to be found via ``sys.executable``;
      2. alongside this source file — the case when running from source;
      3. whatever ``vol`` is on PATH — developer machines.

    Falling back to the bare name keeps the failure message recognisable if
    none of the above exist.
    """
    names = ["vol.exe", "vol"] if os.name == "nt" else ["vol"]
    roots = []
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots.append(Path(os.path.abspath(__file__)).parent)

    for root in roots:
        for name in names:
            candidate = root / name
            if candidate.exists():
                return str(candidate)

    import shutil
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return "vol"


VOL_BIN = _find_vol_binary()


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
            # Real windows.pslist columns: PID PPID ImageFileName Offset(V)
            # Threads Handles SessionId Wow64 CreateTime(3 tokens) ExitTime
            # File-output. CreateTime is ALWAYS exactly 3 space-separated
            # tokens (date, time, "UTC") at indices 8-10 — fixed width,
            # regardless of what follows. The previous parts[9:] was both
            # off-by-one (dropped the date entirely) and unbounded (swept
            # in ExitTime and the trailing "Disabled"/dumped-file marker
            # too), producing garbled multi-timestamp strings especially
            # for processes that had genuinely exited before capture.
            create_time = " ".join(parts[8:11]) if len(parts) > 10 else "1970-01-01 00:00:00"

            # ExitTime is "N/A" (1 token) for still-running processes, or a
            # real 3-token timestamp (same date/time/UTC format) for ones
            # that exited before memory capture — genuinely useful forensic
            # signal (e.g. corroborating an "orphan process" finding) that
            # was previously discarded entirely, not just mis-parsed.
            exit_time = "N/A"
            if len(parts) > 11:
                if parts[11] == "N/A":
                    exit_time = "N/A"
                elif len(parts) > 13:
                    exit_time = " ".join(parts[11:14])

            processes.append({
                "pid": int(parts[0]),
                "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                "image_name": parts[2],
                "create_time": create_time,
                "exit_time": exit_time,
                "vads": [],
                "threads": []
            })

    return processes


def detect_vad_tree_anomalies(vads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    VAD tree manipulation detection beyond the basic private-executable
    filter. Three distinct structural anomaly classes, each checking a
    different manipulation technique:

    1. Unmapped image-type VADs: a VAD tagged as an image type (VadImage/
       VadImageMap — meaning Windows itself recorded it as a PE mapping)
       but with no backing file on disk. Normal PE loading always has a
       mapped file; this combination is the structural signature of a
       manually-mapped or reflectively-loaded PE — the loader never went
       through the normal LoadLibrary path that would leave a file mapping,
       but the VAD metadata still shows an image-type tag.

    2. Overlapping VAD ranges: two VADs in the same process whose address
       ranges intersect. This should be structurally impossible in a valid
       VAD tree (Windows' own memory manager enforces non-overlapping
       regions) — seeing it means either VAD tree corruption/manipulation,
       or (more mundanely) a parsing artifact, which is why this is
       reported as a flag to investigate, not an automatic verdict.

    3. Guard/no-access sandwiching: a PAGE_GUARD or PAGE_NOACCESS region
       immediately adjacent to an executable region. This is a known
       anti-debugging/anti-scanning technique — a single-step or memory
       scan that touches the guard page triggers an exception the malware
       can catch, letting it detect it's being analyzed.

    All three are heuristic signals, not proof — each is reported with the
    specific evidence so an analyst can verify manually.
    """
    findings = {
        "unmapped_image_vads": [],
        "overlapping_vad_ranges": [],
        "guard_page_sandwiching": [],
    }

    IMAGE_TAGS = {"VadImage", "VadImageMap", "VadImg"}
    for v in vads:
        if v.get("tag") in IMAGE_TAGS and not v.get("mapped_file"):
            findings["unmapped_image_vads"].append({
                "start": v.get("start"), "end": v.get("end"),
                "tag": v.get("tag"), "protection": v.get("protection"),
                "note": "VAD tagged as image-type but has no backing file — "
                        "signature of manual/reflective PE mapping.",
            })

    sorted_vads = sorted([v for v in vads if v.get("start_int") is not None],
                          key=lambda v: v["start_int"])
    for i in range(len(sorted_vads) - 1):
        cur, nxt = sorted_vads[i], sorted_vads[i + 1]
        if cur["end_int"] > nxt["start_int"]:
            findings["overlapping_vad_ranges"].append({
                "region_a": {"start": cur.get("start"), "end": cur.get("end")},
                "region_b": {"start": nxt.get("start"), "end": nxt.get("end")},
                "overlap_bytes": cur["end_int"] - nxt["start_int"],
            })

    for i, v in enumerate(sorted_vads):
        prot = str(v.get("protection", "")).upper()
        is_exec = "EXECUTE" in prot
        is_guard = "GUARD" in prot or "NOACCESS" in prot
        if is_exec:
            for neighbor in (sorted_vads[i - 1] if i > 0 else None,
                              sorted_vads[i + 1] if i + 1 < len(sorted_vads) else None):
                if neighbor is None:
                    continue
                n_prot = str(neighbor.get("protection", "")).upper()
                if "GUARD" in n_prot or "NOACCESS" in n_prot:
                    findings["guard_page_sandwiching"].append({
                        "executable_region": {"start": v.get("start"), "end": v.get("end")},
                        "guard_region": {"start": neighbor.get("start"), "end": neighbor.get("end")},
                        "guard_protection": neighbor.get("protection"),
                    })
                    break

    findings["total_anomalies"] = (len(findings["unmapped_image_vads"]) +
                                     len(findings["overlapping_vad_ranges"]) +
                                     len(findings["guard_page_sandwiching"]))
    return findings


def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte buffer."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def classify_entropy(entropy: float) -> str:
    if entropy > 7.5:
        return "ENCRYPTED_PACKED"
    if entropy >= 6.0:
        return "COMPILED_CODE"
    return "DATA_OR_PLAIN_SHELLCODE"


def check_pe_header(data: bytes) -> Dict[str, Any]:
    """Minimal PE header check — MZ magic + optional imported DLL scan via ASCII strings."""
    if len(data) < 2 or data[:2] != b"MZ":
        return {"pe_header_found": False}
    # Cheap import-hint scan: known DLL name strings anywhere in the buffer
    interesting_dlls = [b"ws2_32.dll", b"wininet.dll", b"winhttp.dll",
                         b"advapi32.dll", b"kernel32.dll", b"urlmon.dll"]
    found_dlls = sorted({d.decode() for d in interesting_dlls if d in data.lower()})
    return {"pe_header_found": True, "referenced_dlls": found_dlls}


def extract_strings_from_bytes(data: bytes, min_len: int = 6, cap: int = 50) -> Dict[str, List[str]]:
    """Pull printable ASCII strings and bucket them by IOC-relevant pattern."""
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    raw_strings = [m.group().decode(errors="ignore") for m in pattern.finditer(data)][:2000]

    ip_re = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    domain_re = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    buckets = {"ips": [], "domains": [], "registry_paths": [], "mutexes": [], "file_paths": [], "urls": []}
    for s in raw_strings:
        if "http://" in s.lower() or "https://" in s.lower() or "ftp://" in s.lower():
            buckets["urls"].append(s)
        elif "HKLM\\" in s.upper() or "HKCU\\" in s.upper() or "HKEY_" in s.upper():
            buckets["registry_paths"].append(s)
        elif s.startswith(("Global\\", "Local\\")):
            buckets["mutexes"].append(s)
        elif re.search(r"[A-Za-z]:\\", s):
            buckets["file_paths"].append(s)
        elif ip_re.search(s):
            buckets["ips"].append(s)
        elif domain_re.search(s) and "." in s:
            buckets["domains"].append(s)
    for k in buckets:
        buckets[k] = sorted(set(buckets[k]))[:cap]
    return buckets


def shellcode_heuristic(data: bytes) -> bool:
    """Common shellcode prologues: short jmp, call $+5, push/ret stub."""
    if len(data) < 5:
        return False
    head = data[:6]
    if head[0] == 0xEB:
        return True
    if head[:5] == b"\xE8\x00\x00\x00\x00":
        return True
    if head[0] == 0x68 and len(data) >= 6 and data[5] == 0xC3:
        return True
    return False


def _score_decoded_buffer(decoded: bytes) -> Dict[str, Any]:
    """Shared scoring logic for any decode candidate — IP:port/URL/path hits, printable-ratio sanity check."""
    ip_port_re = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}")
    ip_re = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    url_re = re.compile(rb"https?://[\w./\-]{4,}")
    http_path_re = re.compile(rb"/[\w./\-]{2,40}\.(?:php|dll|bin|exe|dat)")
    printable_re = re.compile(rb"[ -~]{6,}")

    score = 0
    hits = {"ip_ports": [], "ips": [], "urls": [], "http_paths": []}
    for m in ip_port_re.finditer(decoded):
        score += 3
        hits["ip_ports"].append(m.group().decode())
    for m in url_re.finditer(decoded):
        score += 3
        hits["urls"].append(m.group().decode(errors="ignore"))
    for m in http_path_re.finditer(decoded):
        score += 2
        hits["http_paths"].append(m.group().decode(errors="ignore"))
    for m in ip_re.finditer(decoded):
        score += 1
        hits["ips"].append(m.group().decode())

    printable_ratio = len(b"".join(printable_re.findall(decoded))) / max(len(decoded), 1)
    if score > 0 and printable_ratio < 0.15:
        score = max(0, score - 2)
    for k in hits:
        hits[k] = sorted(set(hits[k]))[:10]
    return {"score": score, "printable_ratio": round(printable_ratio, 3), "hits": hits}


def crack_multibyte_xor_config(data: bytes, key_lengths=(2, 3, 4), min_score: int = 3,
                                max_candidates_per_length: int = 20000,
                                max_offsets_per_crib: int = 5000,
                                max_full_decodes: int = 200) -> Optional[Dict[str, Any]]:
    """
    Multi-byte XOR key brute-force — the real next tier above single-byte XOR.
    Full brute force of 2-4 byte keys is 65536/16.7M/4.3B combinations, so
    for 3-4 byte keys this uses a known-plaintext-attack shortcut instead of
    pure brute force: XOR the ciphertext against expected substrings (e.g.
    'http://' or a run of digits+dots for an IP) at every offset to derive
    candidate key bytes, then verify that key against the whole buffer.
    This is the standard practical approach real analysts use for multi-byte
    XOR — full brute force of a 4-byte key space against a large buffer is
    not tractable in seconds, and isn't how this is actually done manually.
    """
    if len(data) < 64:
        return None

    crib_candidates = [b"http://", b"https://", b".php", b"POST /", b"GET /", b"User-Agent"]
    best = None
    full_decodes_done = 0
    seen_keys = set()

    for crib in crib_candidates:
        if full_decodes_done >= max_full_decodes:
            break
        crib_len = len(crib)
        last_offset = len(data) - crib_len
        num_offsets = min(last_offset, max_offsets_per_crib)
        for offset in range(0, num_offsets, 1):
            if full_decodes_done >= max_full_decodes:
                break
            chunk = data[offset:offset + crib_len]
            derived_key = bytes(c ^ k for c, k in zip(chunk, crib))
            for klen in key_lengths:
                if crib_len < klen:
                    continue
                key = derived_key[:klen]
                if len(set(key)) == 1 and key[0] == 0:
                    continue  # all-zero key is a no-op, not a real candidate
                if key in seen_keys:
                    continue  # already tried this exact key from an earlier offset —
                    # common with repeated/similar byte runs in real memory regions;
                    # without this, the full-decode budget can be exhausted on
                    # redundant duplicates before ever reaching a distinct candidate
                seen_keys.add(key)
                if full_decodes_done >= max_full_decodes:
                    break

                # Cheap pre-screen: check a small sample before committing to
                # the expensive full-buffer decode. Only skips candidates that
                # are clearly unpromising even at sample scale — a real hit
                # will still look promising in the first 512 bytes.
                sample = data[:min(512, len(data))]
                sample_decoded = bytes(sample[i] ^ key[i % klen] for i in range(len(sample)))
                sample_scored = _score_decoded_buffer(sample_decoded)
                if sample_scored["score"] < 1 and sample_scored["printable_ratio"] < 0.3:
                    continue

                full_decodes_done += 1
                decoded = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
                scored = _score_decoded_buffer(decoded)
                if scored["score"] >= min_score and (best is None or scored["score"] > best["score"]):
                    best = {
                        "key_hex": key.hex(),
                        "key_length": klen,
                        "derivation_method": f"known-plaintext ('{crib.decode(errors='ignore')}' crib at offset {offset})",
                        "score": scored["score"],
                        "printable_ratio": scored["printable_ratio"],
                        "recovered_indicators": scored["hits"],
                        "confidence": "MEDIUM" if scored["score"] >= 6 else "LOW",
                        "note": "Multi-byte XOR candidate recovered via known-plaintext attack "
                                "(crib-dragging), not exhaustive brute force — exhaustive search "
                                "of a multi-byte key space is not tractable at this buffer size. "
                                "Verify manually before treating as confirmed.",
                    }
    return best


def crack_rc4_config(data: bytes, common_keys: Optional[List[bytes]] = None,
                      min_score: int = 3) -> Optional[Dict[str, Any]]:
    """
    RC4 decryption attempt against a curated list of keys commonly reused
    across malware families and their observed campaigns, plus keys derived
    from strings already found elsewhere in this dump (a common malware
    pattern: reusing a mutex name, campaign ID, or hardcoded string as the
    RC4 key for its own config blob). This is NOT a brute-force of RC4's
    full keyspace — RC4 has no algebraic shortcut like XOR does, so without
    the real key this can only test specific candidates, not search
    exhaustively. A miss here does not mean "not RC4," only "not one of
    these candidate keys."
    """
    def rc4(key: bytes, data: bytes) -> bytes:
        S = list(range(256))
        j = 0
        klen = len(key)
        for i in range(256):
            j = (j + S[i] + key[i % klen]) % 256
            S[i], S[j] = S[j], S[i]
        out = bytearray()
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(out)

    if len(data) < 64:
        return None

    keys = list(common_keys or [])
    keys += [b"123", b"password", b"secret", b"malware", b"config", b"admin123", b"P@ssw0rd"]
    keys = [k for k in keys if k]

    best = None
    for key in keys:
        decoded = rc4(key, data)
        scored = _score_decoded_buffer(decoded)
        if scored["score"] >= min_score and (best is None or scored["score"] > best["score"]):
            best = {
                "key": key.decode(errors="replace"),
                "algorithm": "RC4",
                "score": scored["score"],
                "printable_ratio": scored["printable_ratio"],
                "recovered_indicators": scored["hits"],
                "confidence": "MEDIUM" if scored["score"] >= 6 else "LOW",
                "note": "RC4 candidate decode using a curated key list, not exhaustive search "
                        "(RC4 has no algebraic shortcut for key recovery). A miss means none of "
                        "the tested candidate keys worked, not that RC4 is ruled out.",
            }
    return best


def crack_xor_config(data: bytes, min_score: int = 2) -> Optional[Dict[str, Any]]:
    """
    Single-byte XOR config cracker. Many malware families (Cridex/Feodo-class
    banking trojans especially) keep their C2 config as a XOR-obfuscated blob
    in memory rather than plaintext strings, specifically to defeat plain
    string extraction. This brute-forces all 256 single-byte keys, decodes
    the region under each, and scores the result for C2-relevant patterns
    (IP:port pairs, URLs, HTTP paths). The highest-scoring key/decode is
    returned as a candidate recovered config — NOT a confirmed decode, since
    single-byte XOR can coincidentally produce plausible-looking noise on
    short buffers. Confidence is reported honestly as a candidate, not fact.
    Skips key 0x00 (no-op — would just re-run string extraction) and only
    scores buffers that are reasonably sized (avoids false positives on tiny
    regions where 256 attempts are statistically likely to hit noise).
    """
    if len(data) < 64:
        return None

    ip_port_re = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}")
    ip_re = re.compile(rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    url_re = re.compile(rb"https?://[\w./\-]{4,}")
    http_path_re = re.compile(rb"/[\w./\-]{2,40}\.(?:php|dll|bin|exe|dat)")
    printable_re = re.compile(rb"[ -~]{6,}")

    best = None
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        score = 0
        hits = {"ip_ports": [], "ips": [], "urls": [], "http_paths": []}
        for m in ip_port_re.finditer(decoded):
            score += 3
            hits["ip_ports"].append(m.group().decode())
        for m in url_re.finditer(decoded):
            score += 3
            hits["urls"].append(m.group().decode(errors="ignore"))
        for m in http_path_re.finditer(decoded):
            score += 2
            hits["http_paths"].append(m.group().decode(errors="ignore"))
        for m in ip_re.finditer(decoded):
            score += 1
            hits["ips"].append(m.group().decode())
        # Printable-ratio sanity check: a correct XOR key should produce
        # mostly printable output around the hit, not just a lucky pattern
        # match inside otherwise-random bytes.
        printable_ratio = len(b"".join(printable_re.findall(decoded))) / max(len(decoded), 1)
        if score > 0 and printable_ratio < 0.15:
            score = max(0, score - 2)  # penalize likely-coincidental hits

        if score >= min_score and (best is None or score > best["score"]):
            for k in hits:
                hits[k] = sorted(set(hits[k]))[:10]
            best = {
                "xor_key": f"0x{key:02x}",
                "score": score,
                "printable_ratio": round(printable_ratio, 3),
                "recovered_indicators": hits,
                "confidence": "MEDIUM" if score >= 5 else "LOW",
                "note": "Single-byte XOR candidate decode — verify manually before "
                        "treating as confirmed C2 config; brute force can produce "
                        "coincidental matches, especially on shorter buffers.",
            }
    return best


def dump_and_analyze_region(memory_path: Path, pid: int, base_address: str,
                             work_dir: Path) -> Optional[Dict[str, Any]]:
    """
    Use Volatility 3's windows.vadinfo --dump to materialize this VAD's bytes
    to disk, then run entropy/PE/string analysis on the dumped file.
    Returns None (non-fatal) if the dump fails or the plugin/version doesn't
    support --dump for this VAD.
    """
    try:
        cmd = [VOL_BIN, "-f", str(memory_path), "-o", str(work_dir),
               "windows.vadinfo", "--pid", str(pid), "--dump"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return None
    except Exception:
        return None

    # vadinfo --dump names files like pid.<pid>.vad.<base>-<end>.dmp — find the
    # one matching this base address rather than assuming an exact filename.
    base_norm = base_address.lower().replace("0x", "")
    candidates = list(work_dir.glob(f"pid.{pid}.*"))
    match = None
    for c in candidates:
        if base_norm in c.name.lower():
            match = c
            break
    if not match and candidates:
        match = candidates[0]
    if not match:
        return None

    try:
        data = match.read_bytes()
    except Exception:
        return None
    finally:
        try:
            match.unlink()
        except Exception:
            pass

    if not data:
        return None

    entropy = compute_entropy(data)
    strings_found = extract_strings_from_bytes(data)

    result = {
        "entropy": entropy,
        "entropy_class": classify_entropy(entropy),
        "likely_shellcode": shellcode_heuristic(data),
        "bytes_analyzed": len(data),
        **check_pe_header(data),
        "strings_extracted": strings_found,
    }

    # Always attempt config cracking — plaintext indicators could be decoys
    # while the real C2 config is obfuscated. Escalating tiers: single-byte
    # XOR first (cheapest), then multi-byte XOR, then RC4.
    xor_candidate = crack_xor_config(data)
    if xor_candidate:
        result["xor_config_candidate"] = xor_candidate
    else:
        multibyte_candidate = crack_multibyte_xor_config(data)
        if multibyte_candidate:
            result["multibyte_xor_config_candidate"] = multibyte_candidate
        rc4_candidate = crack_rc4_config(data)
        if rc4_candidate:
            result["rc4_config_candidate"] = rc4_candidate

    # ── Injection Technique Disambiguation ───────────────────────────────────
    # Distinguish between shellcode injection, process hollowing, and
    # reflective DLL injection based on PE header presence and characteristics.
    pe_present = check_pe_header(data).get("pe_header_found", False)
    inj_type = "unknown"
    inj_evidence = []

    if pe_present:
        # PE header in anonymous private RWX memory — reflective DLL or hollowing
        # Check for SizeOfImage sanity: real PE has SizeOfImage in header at offset 0x50
        try:
            size_of_image = int.from_bytes(data[0x50:0x54], "little")
            if 0 < size_of_image < len(data):
                inj_type = "reflective_dll_injection"
                inj_evidence.append(f"PE header present, SizeOfImage=0x{size_of_image:x} fits within region")
                inj_evidence.append("T1055.002 — Portable Executable Injection")
            else:
                inj_type = "process_hollowing"
                inj_evidence.append(f"PE header present but SizeOfImage=0x{size_of_image:x} suspicious")
                inj_evidence.append("T1055.012 — Process Hollowing candidate")
        except Exception:
            inj_type = "pe_in_private_memory"
            inj_evidence.append("PE header found in private executable region (no mapped file)")
        # Check for zeroed-out section headers (classic hollowing indicator)
        if data[0x18:0x20] == b'\x00' * 8:
            inj_type = "process_hollowing"
            inj_evidence.append("Optional header entrypoint field zeroed — process hollowing indicator")
    else:
        if result.get("likely_shellcode"):
            inj_type = "shellcode_injection"
            inj_evidence.append("No PE header, shellcode prologue detected")
            inj_evidence.append("T1055.004 — Asynchronous Procedure Call or raw shellcode")
        elif entropy > 6.5:
            inj_type = "packed_shellcode"
            inj_evidence.append(f"High entropy ({entropy:.2f}) without PE header — packed/encrypted payload")
        else:
            inj_type = "anonymous_exec_region"
            inj_evidence.append("No PE header, low entropy — may be JIT code or legitimate CLR stub")

    result["injection_technique"] = {"type": inj_type, "evidence": inj_evidence, "mitre": _inj_to_mitre(inj_type)}

    # ── Entropy Heatmap ───────────────────────────────────────────────────────
    # Divide region into 4 equal chunks and classify entropy per chunk.
    # Packed malware shows uniformly high entropy; shellcode stubs often show
    # low-entropy header + high-entropy payload — this pattern is forensically
    # significant and cannot be captured by a single region-wide entropy score.
    chunk_size = max(len(data) // 4, 64)
    heatmap = []
    for i in range(4):
        chunk = data[i * chunk_size: (i + 1) * chunk_size]
        if not chunk:
            break
        freq = [0] * 256
        for byte in chunk:
            freq[byte] += 1
        n = len(chunk)
        chunk_entropy = -sum((c / n) * math.log2(c / n) for c in freq if c > 0)
        heatmap.append({
            "chunk": i + 1,
            "offset": f"0x{i * chunk_size:x}",
            "entropy": round(chunk_entropy, 3),
            "class": ("PACKED" if chunk_entropy > 7.2 else
                       "HIGH" if chunk_entropy > 6.0 else
                       "MEDIUM" if chunk_entropy > 4.0 else "LOW"),
        })
    result["entropy_heatmap"] = heatmap

    # RedLine-specific config/artifact scanner — runs in addition to XOR
    redline_hits = scan_redline_config(data)
    if redline_hits:
        result["redline_config_hits"] = redline_hits

    return result


def scan_redline_config(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Scan raw memory bytes for RedLine Stealer-specific config artifacts:
    - C2 HTTP gate paths  (/store/games/index.php and variants)
    - Cleartext IP:port in typical RedLine config format
    - Bot/campaign ID strings (short numeric or alphanumeric identifiers)
    - Known RedLine mutex names
    - .NET assembly metadata strings (MSIL, mscorlib, System.String)
    - Staging artefact paths (screenshots, zips in Temp)

    Returns a dict of hits if any are found, or None if nothing matches.
    This is pattern-based (not probabilistic) — every hit corresponds to
    a concrete byte sequence found in the memory region.
    """
    hits: Dict[str, List[str]] = {
        "c2_paths": [],
        "c2_ips": [],
        "mutex_names": [],
        "dotnet_artifacts": [],
        "staging_paths": [],
        "bot_identifiers": [],
    }

    # C2 gate paths — RedLine uses /store/games/ and similar
    for pat in [
        rb"/store/games/\S+",
        rb"/gate\.php",
        rb"/index\.php",
        rb"/connect\.php",
        rb"/report\.php",
        rb"/panel/\S+",
        rb"http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\S+",
    ]:
        for m in re.finditer(pat, data, re.IGNORECASE):
            val = m.group().decode(errors="ignore")
            if val not in hits["c2_paths"]:
                hits["c2_paths"].append(val)

    # Cleartext IP in typical RedLine config format (x.x.x.x:port)
    for m in re.finditer(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", data):
        val = m.group().decode()
        if val not in hits["c2_ips"]:
            hits["c2_ips"].append(val)

    # Known RedLine mutex patterns
    REDLINE_MUTEXES = [
        b"dcbbwejd", b"jMwfRd", b"RedLine",
        b"8A7F39BC", b"DCR_MUTEX", b"MainMutex",
    ]
    for mutex in REDLINE_MUTEXES:
        if mutex.lower() in data.lower():
            hits["mutex_names"].append(mutex.decode(errors="ignore"))

    # .NET / MSIL artifacts (RedLine is .NET compiled)
    DOTNET_MARKERS = [
        b"mscorlib", b"System.String", b"System.Net.WebClient",
        b"System.IO.Compression", b"mscoree.dll",
        b"BSJB",          # .NET metadata magic
        b"__CorExeMain",  # .NET entry point thunk
    ]
    for marker in DOTNET_MARKERS:
        if marker in data:
            hits["dotnet_artifacts"].append(marker.decode(errors="ignore"))

    # Staging paths — screenshots, zips, temp output
    for m in re.finditer(
        rb"[A-Za-z]:\\[Uu]sers\\[^\\]+\\[Aa]pp[Dd]ata\\[Ll]ocal\\[Tt]emp\\"
        rb"[A-Za-z0-9_\-\.]+\\[A-Za-z0-9_\-\.]+\.(zip|png|jpg|bmp|txt|log|dat)",
        data, re.IGNORECASE
    ):
        val = m.group().decode(errors="ignore")
        if val not in hits["staging_paths"]:
            hits["staging_paths"].append(val)

    # Campaign/bot identifier — short (4-12 char) alphanumeric strings right
    # after "botnet" / "id" / "build" keywords (common in RedLine configs)
    for m in re.finditer(
        rb"(?:botnet|buildid|campaignid|botid)[=: \x00]{1,4}([A-Za-z0-9_\-]{3,16})",
        data, re.IGNORECASE
    ):
        val = m.group(1).decode(errors="ignore")
        if val not in hits["bot_identifiers"]:
            hits["bot_identifiers"].append(val)

    # Deduplicate and cap
    for k in hits:
        hits[k] = sorted(set(hits[k]))[:10]

    # Only return if we found something
    if any(hits.values()):
        found_count = sum(len(v) for v in hits.values())
        return {"hit_count": found_count, "hits": hits}
    return None




def _inj_to_mitre(inj_type: str) -> str:
    """Map injection type string to primary MITRE ATT&CK technique ID."""
    return {
        "shellcode_injection": "T1055.004",
        "process_hollowing": "T1055.012",
        "reflective_dll_injection": "T1055.002",
        "pe_in_private_memory": "T1055",
        "packed_shellcode": "T1027",
        "anonymous_exec_region": "T1055",
        "unknown": "T1055",
    }.get(inj_type, "T1055")



# ═══════════════════════════════════════════════════════════════════════════
# BATCHED PER-PID DRIVER (moved from Engine 3 as part of the architecture fix:
# raw memory-file access now happens ONLY in Engine 2; Engines 3+ consume
# pre-computed JSON only).
#
# ALSO fixes the actual hang: the original Engine 3 called
# `windows.vadinfo --pid X --dump` ONCE PER REGION (e.g. 3 separate calls for
# MsMpEng.exe's 3 regions), each paying full Volatility startup/PDB-scan
# overhead with a 180s timeout — up to tens of minutes of redundant work for
# a handful of suspect PIDs. `--dump` already dumps ALL VADs for a PID in one
# pass, so this now calls it ONCE PER PID and matches every candidate VAD's
# base address against that single dump pass.
# ═══════════════════════════════════════════════════════════════════════════

def _is_private_exec_candidate(vad: Dict[str, Any]) -> bool:
    """Same criteria as Engine 3's is_private_exec_region — duplicated here
    (not imported) to keep Engine 2 fully standalone, since it must run
    before Engine 3 exists in the pipeline and shouldn't depend on it."""
    protection = (vad.get("protection") or "").upper()
    if "EXECUTE" not in protection:
        return False
    if not vad.get("private", False):
        return False
    if vad.get("mapped_file") is not None:
        return False
    size = vad.get("size", 0)
    if not (4096 <= size <= 256 * 1024 * 1024):
        return False
    if any(excl in protection for excl in ("GUARD", "WOW64")):
        return False
    return True


def enrich_private_exec_vads_with_byte_analysis(memory_path: Path, processes: List[Dict[str, Any]]) -> None:
    """
    For every process with at least one private-exec-candidate VAD, dump that
    PID's VAD tree ONCE via `windows.vadinfo --dump`, then run entropy/PE/
    string/XOR/RC4/RedLine-config analysis on each candidate VAD's dumped
    bytes. Mutates each matching VAD dict in place, adding "region_analysis".
    Non-fatal on any per-PID failure — analysis is a bonus, not required for
    the pipeline to proceed.
    """
    candidates_by_pid = {}
    for proc in processes:
        pid = proc.get("pid")
        cand_vads = [v for v in proc.get("vads", []) if _is_private_exec_candidate(v)]
        if cand_vads:
            candidates_by_pid[pid] = cand_vads

    if not candidates_by_pid:
        print("  ℹ️  No private-exec candidate VADs found — skipping byte-level analysis")
        return

    print(f"  🔬 Byte-level analysis: {len(candidates_by_pid)} PID(s), "
          f"{sum(len(v) for v in candidates_by_pid.values())} candidate region(s) total")

    for pid, cand_vads in candidates_by_pid.items():
        work_dir = Path(tempfile.mkdtemp(prefix=f"e2_vaddump_{pid}_"))
        try:
            cmd = [VOL_BIN, "-f", str(memory_path), "-o", str(work_dir),
                   "windows.vadinfo", "--pid", str(pid), "--dump"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            except subprocess.TimeoutExpired:
                print(f"    ⚠️  PID {pid}: vadinfo --dump timed out (180s) — skipping")
                continue
            if result.returncode != 0:
                print(f"    ⚠️  PID {pid}: vadinfo --dump failed (exit {result.returncode}) — skipping")
                continue

            dumped_files = list(work_dir.glob(f"pid.{pid}.*"))
            if not dumped_files:
                print(f"    ⚠️  PID {pid}: no dump files produced — skipping")
                continue

            analyzed = 0
            for vad in cand_vads:
                base_norm = (vad.get("start") or "").lower().replace("0x", "")
                match = next((f for f in dumped_files if base_norm in f.name.lower()), None)
                if not match:
                    continue
                try:
                    data = match.read_bytes()
                except Exception:
                    continue
                if not data:
                    continue

                entropy = compute_entropy(data)
                strings_found = extract_strings_from_bytes(data)
                analysis = {
                    "entropy": entropy,
                    "entropy_class": classify_entropy(entropy),
                    "likely_shellcode": shellcode_heuristic(data),
                    "bytes_analyzed": len(data),
                    "hex_preview": data[:64].hex(),
                    **check_pe_header(data),
                    "strings_extracted": strings_found,
                }
                xor_candidate = crack_xor_config(data)
                if xor_candidate:
                    analysis["xor_config_candidate"] = xor_candidate
                else:
                    multibyte_candidate = crack_multibyte_xor_config(data)
                    if multibyte_candidate:
                        analysis["multibyte_xor_config_candidate"] = multibyte_candidate
                    rc4_candidate = crack_rc4_config(data)
                    if rc4_candidate:
                        analysis["rc4_config_candidate"] = rc4_candidate

                pe_present = analysis.get("pe_header_found", False)
                inj_type = "unknown"
                inj_evidence = []
                if pe_present:
                    try:
                        size_of_image = int.from_bytes(data[0x50:0x54], "little")
                        if 0 < size_of_image < len(data):
                            inj_type = "reflective_dll_injection"
                            inj_evidence.append(f"PE header present, SizeOfImage=0x{size_of_image:x} fits within region")
                            inj_evidence.append("T1055.002 — Portable Executable Injection")
                        else:
                            inj_type = "process_hollowing"
                            inj_evidence.append(f"PE header present but SizeOfImage=0x{size_of_image:x} suspicious")
                            inj_evidence.append("T1055.012 — Process Hollowing candidate")
                    except Exception:
                        inj_type = "pe_in_private_memory"
                        inj_evidence.append("PE header found in private executable region (no mapped file)")
                    if data[0x18:0x20] == b'\x00' * 8:
                        inj_type = "process_hollowing"
                        inj_evidence.append("Optional header entrypoint field zeroed — process hollowing indicator")
                else:
                    if analysis.get("likely_shellcode"):
                        inj_type = "shellcode_injection"
                        inj_evidence.append("No PE header, shellcode prologue detected")
                        inj_evidence.append("T1055.004 — Asynchronous Procedure Call or raw shellcode")
                    elif entropy > 6.5:
                        inj_type = "packed_shellcode"
                        inj_evidence.append(f"High entropy ({entropy:.2f}) without PE header — packed/encrypted payload")
                    else:
                        inj_type = "anonymous_exec_region"
                        inj_evidence.append("No PE header, low entropy — may be JIT code or legitimate CLR stub")
                analysis["injection_technique"] = {"type": inj_type, "evidence": inj_evidence, "mitre": _inj_to_mitre(inj_type)}

                chunk_size = max(len(data) // 4, 64)
                heatmap = []
                for i in range(4):
                    chunk = data[i * chunk_size: (i + 1) * chunk_size]
                    if not chunk:
                        break
                    freq = [0] * 256
                    for byte in chunk:
                        freq[byte] += 1
                    n = len(chunk)
                    chunk_entropy = -sum((c / n) * math.log2(c / n) for c in freq if c > 0)
                    heatmap.append({
                        "chunk": i + 1, "offset": f"0x{i * chunk_size:x}",
                        "entropy": round(chunk_entropy, 3),
                        "class": ("PACKED" if chunk_entropy > 7.2 else
                                  "HIGH" if chunk_entropy > 6.0 else
                                  "MEDIUM" if chunk_entropy > 4.0 else "LOW"),
                    })
                analysis["entropy_heatmap"] = heatmap

                redline_hits = scan_redline_config(data)
                if redline_hits:
                    analysis["redline_config_hits"] = redline_hits

                vad["region_analysis"] = analysis
                analyzed += 1

            print(f"    ✓ PID {pid}: {analyzed}/{len(cand_vads)} region(s) analyzed")
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)




def dump_and_hash_process_image(memory_path, pid: int, work_dir: str) -> Optional[Dict[str, Any]]:
    """
    Pull the actual backing executable image for a process straight out of
    memory and hash it. Moved here from Engine 6 as part of the pipeline
    architecture fix: raw memory-file access happens ONLY in Engine 2.

    Uses windows.dumpfiles (NOT windows.pslist --dump, which does not exist
    as a flag on that plugin).
    windows.dumpfiles dumps EVERY memory-mapped file backing the process
    (its .exe AND all loaded DLLs), so multiple files land in work_dir; the
    executable is selected as the largest .img/.dat file produced, since
    DLLs are consistently smaller than the process's own main image for a
    userland process.
    Non-fatal: returns None if Volatility's dump fails for this PID.
    """
    import hashlib, glob as globmod
    try:
        cmd = [VOL_BIN, "-f", str(memory_path), "-o", str(work_dir),
               "windows.dumpfiles", "--pid", str(pid)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        # FIX: don't give up the moment returncode != 0. dumpfiles dumps
        # multiple file objects per process (the EXE plus every loaded
        # DLL) and can crash partway through — e.g. it successfully writes
        # the real EXE first, then hits a LATER file object whose internal
        # Windows name contains corrupted/non-UTF8 bytes (common for
        # generic objects like SharedCacheMap), which macOS's filesystem
        # (APFS) refuses to create as a filename, crashing the whole `vol`
        # process. That crash does not erase files already written before
        # it — checking returncode alone and returning None discarded a
        # perfectly good result whenever this happened. Check what's
        # actually in work_dir regardless of how the process exited.
        if result.returncode != 0:
            print(f"    [dumpfiles] vol exited {result.returncode} for PID {pid} "
                  f"(likely a later file object with an unwriteable name — checking "
                  f"work_dir for anything it wrote before crashing)")
    except Exception as e:
        print(f"    [dumpfiles] exception for PID {pid}: {e}")
        result = None

    candidates = (globmod.glob(os.path.join(work_dir, "*.img")) +
                  globmod.glob(os.path.join(work_dir, "*.dat")))
    candidates = [c for c in candidates if os.path.getsize(c) > 0]

    if not candidates:
        # dumpfiles produced nothing usable at all (crashed before writing
        # anything, or genuinely has no disk-backed file objects). Fall
        # back to windows.memmap --dump: it names output files by numeric
        # memory offset, not by an internal object name read from memory,
        # so it structurally cannot hit the same illegal-byte-sequence
        # crash. Trade-off: memmap dumps the whole process address space
        # as page-granularity blocks rather than cleanly separating "this
        # is the EXE" from "this is a DLL", so this is a best-effort
        # whole-memory-snapshot hash, not a precise single-file hash —
        # labeled accordingly in the returned dict.
        print(f"    [dumpfiles] no usable output for PID {pid} — falling back to windows.memmap --dump")
        try:
            cmd2 = [VOL_BIN, "-f", str(memory_path), "-o", str(work_dir),
                    "windows.memmap", "--pid", str(pid), "--dump"]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=180)
        except Exception as e:
            print(f"    [memmap fallback] exception for PID {pid}: {e}")
            return None

        mem_candidates = globmod.glob(os.path.join(work_dir, f"pid.{pid}*.dmp"))
        mem_candidates = [c for c in mem_candidates if os.path.getsize(c) > 0]
        if not mem_candidates:
            print(f"    [memmap fallback] produced no usable output for PID {pid} either "
                  f"(vol exited {result2.returncode if 'result2' in dir() else '?'})")
            return None

        dump_path = max(mem_candidates, key=os.path.getsize)
        try:
            data = open(dump_path, "rb").read()
        finally:
            for c in mem_candidates:
                try:
                    os.remove(c)
                except Exception:
                    pass

        if not data:
            return None

        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "size_bytes": len(data),
            "source": "process_memory_snapshot (Engine 2, windows.memmap fallback — "
                      "whole address-space block, not a precisely isolated EXE image; "
                      "dumpfiles could not write output for this PID due to a corrupted/"
                      "non-UTF8 internal object name macOS's filesystem rejected)",
        }

    # Primary path: dumpfiles produced usable output. The executable is
    # selected as the largest .img/.dat file, since DLLs are consistently
    # smaller than the process's own main image for a userland process.
    dump_path = max(candidates, key=os.path.getsize)
    try:
        data = open(dump_path, "rb").read()
    finally:
        for c in candidates:
            try:
                os.remove(c)
            except Exception:
                pass

    if not data:
        return None

    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size_bytes": len(data),
        "source": "process_memory_image_dump (Engine 2, windows.dumpfiles)",
    }


def enrich_processes_with_image_hashes(memory_path: Path, processes: List[Dict[str, Any]]) -> None:
    """
    Batched per-PID hash extraction — moved from Engine 6 as part of the
    pipeline architecture fix (memory-file access confined to Engine 2 only).
    Reuses the same private-exec-candidate PID list as the byte-analysis
    pass above, since these are exactly the processes downstream engines
    need real hashes for — no separate raw-memory pass required.
    Mutates each candidate process dict in place, adding "file_hashes".
    """
    candidate_pids = [
        proc.get("pid") for proc in processes
        if any(_is_private_exec_candidate(v) for v in proc.get("vads", []))
    ]
    if not candidate_pids:
        print("  ℹ️  No private-exec candidate PIDs — skipping image hash extraction")
        return

    print(f"  🔐 Extracting real file hashes for {len(candidate_pids)} candidate PID(s)...")
    by_pid = {p.get("pid"): p for p in processes}
    for pid in candidate_pids:
        proc = by_pid.get(pid)
        if not proc:
            continue
        work_dir = tempfile.mkdtemp(prefix=f"e2_hashdump_{pid}_")
        try:
            hashes = dump_and_hash_process_image(memory_path, pid, work_dir)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
        if hashes:
            proc["file_hashes"] = hashes
            print(f"    ✓ PID {pid} ({proc.get('image_name', 'Unknown')}): "
                  f"SHA256 {hashes['sha256'][:16]}...")
        else:
            print(f"    ⚠️  PID {pid} ({proc.get('image_name', 'Unknown')}): hash extraction failed")


def run_malfind_reference_scan(memory_path: Path) -> List[Dict[str, Any]]:
    """
    Run Volatility 3's windows.malfind ONCE for the whole dump, as a
    methodological cross-validation reference — moved here from Engine 6 as
    part of the pipeline architecture fix (memory-file access confined to
    Engine 2 only). Returns raw (pid, process) hits; the set-comparison
    against this pipeline's own classifications is pure JSON/Python logic
    and stays in Engine 6, reading this precomputed list.
    Non-fatal: returns [] if malfind itself fails on this dump/OS version.
    """
    try:
        result = subprocess.run(
            [VOL_BIN, "-f", str(memory_path), "windows.malfind"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            print(f"  ⚠️  [malfind reference scan] vol exited {result.returncode}: "
                  f"{(result.stderr or result.stdout or '').strip()[-300:]}")
            return []
    except Exception as e:
        print(f"  ⚠️  [malfind reference scan] exception: {e}")
        return []

    hits = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[2].lower().startswith("0x"):
            hits.append({"pid": int(parts[0]), "process": parts[1] if len(parts) > 1 else "?"})
    print(f"  ✓ malfind reference scan: {len(hits)} hit(s)")
    return hits


def extract_vads_for_process(memory_path: Path, pid: int) -> List[Dict[str, Any]]:
    """Extract VAD regions for a specific process"""

    result = run_volatility(memory_path, "windows.vadinfo", ["--pid", str(pid)], timeout=60)

    vads = []
    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip() or line.strip().startswith("PID ") or "---" in line or "Volatility" in line:
            continue

        parts = line.split()
        # Verified real columns (confirmed against actual `vol windows.vadinfo`
        # output): PID(0) Process(1) Offset(2) StartVPN(3) EndVPN(4) Tag(5)
        # Protection(6) CommitCharge(7) PrivateMemory(8) Parent(9) File(10..)
        # FileOutput(last). File can contain no spaces in practice (Windows
        # system paths don't), but the join handles it defensively anyway.
        # PrivateMemory is Volatility's OWN explicit 0/1 flag for whether
        # this is private/anonymous memory — using it directly instead of
        # pattern-matching a file path, since the previous two attempts
        # (guessed column index, then a file-path regex) both failed against
        # real output that doesn't use \Device\ or drive-letter prefixes
        # (confirmed real paths look like \Windows\SysWOW64\ntdll.dll).
        if len(parts) >= 11 and parts[0].isdigit():
            try:
                start = int(parts[3], 16)
                end = int(parts[4], 16)
                size = end - start
                protection = parts[6]
                vad_tag = parts[5]

                private_memory_flag = parts[8]
                is_private = private_memory_flag == "1"

                file_parts = parts[10:]
                if file_parts and file_parts[-1] == "Disabled":
                    file_parts = file_parts[:-1]
                file_field = " ".join(file_parts) if file_parts else "N/A"
                mapped_file = None if file_field in ("N/A", "-", "") else file_field

                vads.append({
                    "start": parse_hex_address(hex(start)),
                    "end": parse_hex_address(hex(end)),
                    "start_int": start,
                    "end_int": end,
                    "size": size,
                    "protection": protection,
                    "tag": vad_tag,
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

        # Real windows.dlllist rows trail the path with a LoadTime column
        # (date/time/tz, or literal "N/A"), and Path() can't be used to
        # isolate the filename here: this script runs on macOS, where
        # pathlib treats only "/" as a separator, so Path(...).name on a
        # Windows "C:\Windows\system32\x.dll" style path returns the whole
        # string unsplit. Extract the drive-letter path with a regex
        # instead. The path is bounded by the trailing LoadTime column
        # (not by the first whitespace) because Windows paths legitimately
        # contain spaces (e.g. "Program Files", "Windows Defender") — an
        # earlier version of this regex used \S* and silently truncated
        # any such path, extracting the wrong module name.
        joined = " ".join(remaining).strip()
        if not joined:
            continue

        path_match = re.search(
            r'[A-Za-z]:\\.*?(?=\s+(?:\d{4}-\d{2}-\d{2}|N/A)\s|\s*$)', joined
        )
        if not path_match:
            continue
        path = path_match.group()
        module_name = path.rsplit("\\", 1)[-1] if "\\" in path else path

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

        # Real windows.getsids columns: PID  Process  SID  Name
        #        3692  powershell.exe  S-1-5-21-...-4120  DESKTOP-ABC\Elon
        # (previously read as PID [1]=SID [2]=Name — missing the Process
        # column entirely, so every SID/username pair was shifted one
        # column left: "sid" ended up holding the process name and
        # "username"/"username_full" held the actual SID string. Name can
        # itself contain spaces — e.g. "Mandatory Label\High Mandatory
        # Level" — so split with maxsplit to keep it intact as one field.)
        parts = line.split(None, 3)
        if len(parts) >= 3 and parts[0].isdigit():
            try:
                pid = int(parts[0])
                sid = parts[2]
                username = parts[3] if len(parts) > 3 else None

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


INTERESTING_ENVAR_NAMES = {
    "PATH", "TEMP", "TMP", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "ALL_PROXY", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
}


def extract_all_envars(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract per-process environment variables via windows.envars, filtered to
    operationally-relevant names (proxy config, PATH, temp dirs) — attacker
    environment tampering (e.g. injected HTTP_PROXY, PATH prepended with a
    writable dir) shows up here."""
    print("🌎 Extracting environment variables via Volatility 3 windows.envars...")

    result = run_volatility(memory_path, "windows.envars", timeout=300)
    envars_by_pid = {}

    if result.returncode != 0:
        print("⚠️ Environment variable extraction unavailable")
        return envars_by_pid

    lines = clean_vol_output(result.stdout)

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["PID", "---", "Volatility", "Process", "Variable", "Value"]):
            continue

        # Format: PID  Process  Block  Variable  Value
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit():
            continue

        try:
            pid = int(parts[0])
            variable = parts[3]
            value = parts[4]

            if variable.upper() not in INTERESTING_ENVAR_NAMES:
                continue

            entry = {"variable": variable, "value": value}
            if variable.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                entry["flag"] = "PROXY_CONFIGURED"

            if pid not in envars_by_pid:
                envars_by_pid[pid] = []
            envars_by_pid[pid].append(entry)
        except (ValueError, IndexError):
            continue

    return envars_by_pid


def enrich_process_with_envars(proc: Dict[str, Any], envars_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Attach filtered environment variables to a process."""
    proc["environment_variables"] = envars_by_pid.get(proc["pid"], [])


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

        parts = line.split(None, 6)  # split into at most 7 fields so Name can contain spaces
        if len(parts) < 5 or not parts[0].isdigit():
            continue

        try:
            pid = int(parts[0])
            # Real windows.handles columns: PID  Process  Offset  HandleValue  Type  GrantedAccess  Name
            # (previously read as PID [1] Type[2] GrantedAccess[3] Name[4:] — off by
            # two columns, comparing the hex Offset field against "Process"/"Thread",
            # which can never match, so every handle was silently dropped)
            handle_type = parts[4] if len(parts) > 4 else None
            granted_access = parts[5] if len(parts) > 5 else None
            name = parts[6] if len(parts) > 6 else None

            # Track process/thread handles (cross-process relevance) plus
            # Mutant handles (named mutex enumeration for malware family ID)
            if handle_type in ["Process", "Thread", "Mutant"]:
                entry = {
                    "type": handle_type,
                    "granted_access": granted_access,
                    "name": name
                }

                # Extract target PID from name. Real Volatility 3 format for
                # Thread handles is "Tid 556 Pid 3812" (no parentheses) —
                # previously matched only a "(1234)" pattern that never
                # appears in actual output, so target_pid was always None.
                target_pid = None
                if name:
                    pid_match = re.search(r'\bPid[:\s]+(\d+)', name) or re.search(r'\((\d+)\)', name)
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


PERSISTENCE_REGISTRY_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]


def extract_registry_persistence(memory_path: Path) -> List[Dict[str, Any]]:
    """
    MITRE T1547.001 (Registry Run Keys / Startup Folder) detection — queries
    the standard auto-start registry locations via Volatility 3's
    windows.registry.printkey. Any value found here is a program Windows
    will launch automatically at logon, which is exactly how a large share
    of malware survives a reboot. Non-fatal per-key: a missing/inaccessible
    key doesn't abort the others.
    """
    findings = []
    for key_path in PERSISTENCE_REGISTRY_KEYS:
        try:
            result = run_volatility(memory_path, "windows.registry.printkey",
                                     extra_args=["--key", key_path], timeout=120)
        except Exception as e:
            print(f"    [persistence] error querying '{key_path}': {e}")
            continue
        if result.returncode != 0:
            continue  # key not present in this hive — normal, not an error

        for line in clean_vol_output(result.stdout):
            if not line.strip() or any(skip in line for skip in ["Key", "Last Write", "Volatility", "---", "Progress"]):
                continue
            parts = line.split()
            reg_type_idx = next((i for i, p in enumerate(parts)
                                  if p in ("REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",
                                           "REG_MULTI_SZ", "REG_QWORD")), None)
            if reg_type_idx is None:
                continue
            value_type = parts[reg_type_idx]
            remainder = parts[reg_type_idx + 1:]
            if not remainder:
                continue
            value_name = remainder[0]
            value_data = " ".join(remainder[1:]) if len(remainder) > 1 else ""
            findings.append({
                "registry_key": key_path,
                "value_type": value_type,
                "value_name": value_name,
                "value_data": value_data,
                "mitre_technique": "T1547.001",
            })
    return findings


def extract_service_persistence(memory_path: Path) -> List[Dict[str, Any]]:
    """
    MITRE T1543.003 (Windows Service) detection — enumerates services via
    Volatility 3's windows.svcscan. A malicious service is a very common
    persistence mechanism (survives reboot, runs as SYSTEM, blends in among
    dozens of legitimate services). Flags services whose binary path looks
    suspicious (non-standard install location, no path at all, or an
    unsigned-looking loose executable name) for analyst attention — this is
    a heuristic flag, not a verdict.
    """
    try:
        result = run_volatility(memory_path, "windows.svcscan", timeout=180)
    except Exception as e:
        print(f"    [persistence] windows.svcscan error: {e}")
        return []
    if result.returncode != 0:
        print(f"    [persistence] windows.svcscan failed: {(result.stderr or '').strip()[-200:]}")
        return []

    STANDARD_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")
    services = []
    current = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            if current:
                services.append(current)
                current = {}
            continue
        if line.startswith("Offset:"):
            if current:
                services.append(current)
            current = {}
        for field in ("PID", "Order", "Start", "State", "Type", "Name", "Display", "Binary"):
            if line.startswith(field + ":"):
                current[field.lower()] = line.split(":", 1)[1].strip()
    if current:
        services.append(current)

    flagged = []
    for svc in services:
        binary = (svc.get("binary") or "").lower()
        suspicious = False
        reasons = []
        if not binary or binary in ("-", "n/a"):
            suspicious = True
            reasons.append("no binary path recorded")
        elif not binary.startswith(STANDARD_DIRS) and "\\windows\\" not in binary:
            suspicious = True
            reasons.append("binary installed outside standard Windows directories")
        if suspicious:
            flagged.append({
                "service_name": svc.get("name", "?"),
                "display_name": svc.get("display", "?"),
                "binary_path": svc.get("binary", "?"),
                "state": svc.get("state", "?"),
                "start_type": svc.get("start", "?"),
                "flag_reasons": reasons,
                "mitre_technique": "T1543.003",
            })
    return {"total_services_scanned": len(services), "flagged_services": flagged}


def extract_file_artifacts(memory_path: Path) -> List[Dict[str, Any]]:
    """
    Extract forensically interesting file artifacts using Volatility 3's
    windows.filescan. Targets browser data, archives, screenshots, and
    temp directory contents commonly used by infostealers like RedLine.
    """
    print("📂 Extracting file artifacts via Volatility 3 windows.filescan...")

    result = run_volatility(memory_path, "windows.filescan.FileScan", timeout=300)
    artifacts = []

    if result.returncode != 0:
        print(f"⚠️ windows.filescan failed (exit {result.returncode}): "
              f"{(result.stderr or result.stdout or '').strip()[-500:]}")
        return artifacts

    # Patterns for forensically interesting files
    BROWSER_DATA_PATTERNS = [
        "Login Data", "Cookies", "Web Data", "History", "Bookmarks",
        "Local State", "Preferences",
    ]
    BROWSER_PATHS = ["User Data", "Chrome", "Edge", "Firefox", "Opera", "Brave"]

    lines = clean_vol_output(result.stdout)
    for line in lines:
        if not line.strip() or any(skip in line for skip in ["Offset", "---", "Volatility", "Progress"]):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # filescan output: Offset  Name  File output
        # The third column is Volatility's dump-status marker (literal
        # "Disabled" when --dump wasn't passed, or a dumped filename). Since
        # Windows paths can legitimately contain spaces, we can't just take
        # parts[1] alone — but we must strip this trailing marker or it gets
        # silently appended onto every extracted path (e.g. "...\oneetx.exe
        # Disabled" instead of "...\oneetx.exe").
        offset = parts[0]
        rest = parts[1:]
        if rest and rest[-1] == "Disabled":
            rest = rest[:-1]
        file_path = " ".join(rest)
        file_path_lower = file_path.lower()

        # Classify file type
        file_type = None

        # Browser data files
        if any(bp.lower() in file_path_lower for bp in BROWSER_PATHS):
            if any(bd.lower() in file_path_lower for bd in BROWSER_DATA_PATTERNS):
                file_type = "browser_data"

        # Archives in temp (exfiltration staging)
        if file_type is None and ".zip" in file_path_lower:
            if "temp" in file_path_lower or "tmp" in file_path_lower or "appdata" in file_path_lower:
                file_type = "archive"

        # Screenshots
        if file_type is None and any(ext in file_path_lower for ext in [".png", ".jpg", ".bmp", ".jpeg"]):
            if "temp" in file_path_lower or "tmp" in file_path_lower or "desktop" in file_path_lower:
                file_type = "screenshot"

        # Suspicious executables in temp
        if file_type is None and any(ext in file_path_lower for ext in [".exe", ".dll", ".bat", ".ps1", ".vbs"]):
            if "temp" in file_path_lower or "tmp" in file_path_lower:
                file_type = "temp_executable"

        # Wallet/crypto files
        if file_type is None and any(w in file_path_lower for w in ["wallet.dat", "wallet", "electrum", "exodus", "metamask"]):
            file_type = "crypto_wallet"

        if file_type:
            artifacts.append({
                "file_path": file_path,
                "file_type": file_type,
                "physical_offset": offset,
            })

    print(f"   Found {len(artifacts)} forensic file artifacts")
    return artifacts


def extract_network_connections(memory_path: Path) -> Dict[int, List[Dict[str, Any]]]:
    """Extract network connections from memory using netscan"""
    print("🌐 Extracting network connections via Volatility 3 windows.netscan...")

    result = run_volatility(memory_path, "windows.netscan", timeout=120)
    connections_by_pid = {}

    if result.returncode != 0:
        print(f"⚠️ windows.netscan failed (exit {result.returncode}): "
              f"{(result.stderr or result.stdout or '').strip()[-500:]}")
        print("⚠️ Trying windows.netstat as fallback...")
        result = run_volatility(memory_path, "windows.netstat", timeout=120)
        if result.returncode != 0:
            print(f"⚠️ windows.netstat also failed (exit {result.returncode}): "
                  f"{(result.stderr or result.stdout or '').strip()[-500:]}")
            print("⚠️ Network extraction unavailable for this dump")
            return connections_by_pid

    lines = clean_vol_output(result.stdout)

    STATES = {"CLOSED", "LISTENING", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED",
              "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
              "TIME_WAIT", "DELETE_TCB", "CLOSE"}
    ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^[0-9a-fA-F:]+$')

    for line in lines:
        if not line.strip():
            continue
        if any(skip in line for skip in ["Offset", "Proto", "Local", "---", "Volatility"]):
            continue

        # Real windows.netscan columns: Offset Proto LocalAddr LocalPort
        # ForeignAddr ForeignPort [State] PID Owner [Created] — State is
        # absent for UDP rows. Anchor on the Proto column (TCPv4/UDPv6/etc)
        # instead of guessing fixed positions, since column count varies.
        parts = line.split()
        proto_idx = next((i for i, p in enumerate(parts)
                           if p.upper() in ("TCPV4", "TCPV6", "UDPV4", "UDPV6")), None)
        if proto_idx is None or len(parts) < proto_idx + 6:
            continue

        proto = parts[proto_idx]
        local_addr = parts[proto_idx + 1]
        local_port = parts[proto_idx + 2]
        foreign_addr = parts[proto_idx + 3]
        foreign_port = parts[proto_idx + 4]
        next_field = parts[proto_idx + 5]

        if next_field.upper() in STATES:
            state = next_field
            pid_field = parts[proto_idx + 6] if len(parts) > proto_idx + 6 else None
        else:
            state = "N/A"  # UDP has no state column
            pid_field = next_field

        if not pid_field or not pid_field.isdigit():
            continue
        pid = int(pid_field)

        if not (foreign_port.isdigit() and ip_re.match(foreign_addr) and foreign_addr not in ("0.0.0.0", "*", "::")):
            continue  # skip listening/wildcard sockets — no remote endpoint to report

        entry = {
            "local_ip": local_addr,
            "local_port": int(local_port) if local_port.isdigit() else local_port,
            "remote_ip": foreign_addr,
            "remote_port": int(foreign_port),
            "state": state,
            "protocol": proto,
        }
        connections_by_pid.setdefault(pid, []).append(entry)

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
    mutant_handles = [h for h in handles if h.get("type") == "Mutant"]

    proc["handle_analysis"] = {
        "total_handles": len(handles),
        "openprocess_handles": openprocess_handles,
        "thread_handles": thread_handles,
        "mutant_handles": mutant_handles,
        "cross_process_handle_count": len(openprocess_handles) + len(thread_handles)
    }


def enrich_process_with_network(proc: Dict[str, Any], connections_by_pid: Dict[int, List[Dict[str, Any]]]) -> None:
    """Add network connection information to a process"""
    pid = proc["pid"]
    proc["network_connections"] = connections_by_pid.get(pid, [])


def enrich_process_relationships(processes: List[Dict[str, Any]]) -> None:
    """Add parent image names, orphan detection, and process lineage"""
    pid_to_name = {proc["pid"]: proc["image_name"] for proc in processes}
    pid_set = set(pid_to_name.keys())
    pid_to_proc = {proc["pid"]: proc for proc in processes}

    for proc in processes:
        ppid = proc.get("ppid", 0)
        proc["parent_image_name"] = pid_to_name.get(ppid, "UNKNOWN")

        # Orphan detection: parent PID not in active process list
        proc["orphan_parent"] = ppid != 0 and ppid not in pid_set
        if proc["orphan_parent"]:
            proc["orphan_note"] = f"Parent PID {ppid} not in process list (exited before capture)"

        # Build process lineage (walk up parent chain)
        lineage = []
        current_pid = ppid
        depth = 0
        visited = set()
        while current_pid in pid_to_proc and current_pid not in visited:
            visited.add(current_pid)
            lineage.append(current_pid)
            current_pid = pid_to_proc[current_pid].get("ppid", 0)
            depth += 1
        proc["process_depth"] = depth
        proc["process_lineage"] = lineage


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


def extract_processes_psscan(memory_path: Path) -> List[Dict[str, Any]]:
    """
    Extract processes via Volatility 3 windows.psscan (physical pool-tag scan).
    Unlike pslist (which walks the PsActiveProcessHead linked list and can be
    fooled by DKOM unlinking), psscan finds EPROCESS structures directly in
    physical memory regardless of whether they're linked into the active list.
    Any PID present here but absent from pslist is a hidden-process indicator.
    Non-fatal: returns [] on any failure so this never breaks the pipeline.
    """
    print("🔍 Cross-view scan: Volatility 3 windows.psscan...")
    try:
        result = run_volatility(memory_path, "windows.psscan", timeout=300)
        if result.returncode != 0:
            print(f"⚠️ psscan failed (non-fatal, cross-view check skipped): {result.stderr[:200]}")
            return []
    except Exception as e:
        print(f"⚠️ psscan error (non-fatal, cross-view check skipped): {e}")
        return []

    entries = []
    for line in clean_vol_output(result.stdout):
        if not line.strip() or "PID" in line or "---" in line or "Volatility" in line:
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            entries.append({
                "pid": int(parts[0]),
                "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                "image_name": parts[2],
            })
    return entries


def build_cross_view_analysis(pslist_processes: List[Dict[str, Any]],
                               psscan_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare the linked-list process view (pslist) against the pool-scan view
    (psscan) to surface DKOM-style hidden processes. Additive-only — this does
    not modify the existing `processes` list, it just adds a summary block.
    """
    pslist_pids = {p["pid"] for p in pslist_processes}
    psscan_pids = {e["pid"] for e in psscan_entries}

    if not psscan_entries:
        return {
            "scan_performed": False,
            "note": "windows.psscan unavailable or failed — cross-view check skipped",
            "pslist_only": [],
            "psscan_only": [],
            "hidden_processes_detected": 0,
        }

    hidden = [e for e in psscan_entries if e["pid"] not in pslist_pids]
    pslist_only_pids = sorted(pslist_pids - psscan_pids)

    return {
        "scan_performed": True,
        "pslist_count": len(pslist_pids),
        "psscan_count": len(psscan_pids),
        "both_lists_count": len(pslist_pids & psscan_pids),
        "pslist_only": pslist_only_pids,
        "psscan_only": [
            {"pid": e["pid"], "ppid": e["ppid"], "image_name": e["image_name"],
             "note": "Present in physical pool scan but NOT in active process list — possible DKOM/hidden process"}
            for e in hidden
        ],
        "hidden_processes_detected": len(hidden),
    }


def extract_modules_modscan(memory_path: Path) -> List[Dict[str, Any]]:
    """
    Extract loaded modules via Volatility 3 windows.modscan (pool-tag scan for
    LDR_DATA_TABLE_ENTRY), independent of the PEB module list walked elsewhere.
    A module here with no corresponding entry in a process's PEB-derived module
    list is a module hidden from normal enumeration. Non-fatal on failure.
    """
    print("🔍 Cross-view scan: Volatility 3 windows.modscan...")
    try:
        result = run_volatility(memory_path, "windows.modscan", timeout=300)
        if result.returncode != 0:
            print(f"⚠️ modscan failed (non-fatal): {result.stderr[:200]}")
            return []
    except Exception as e:
        print(f"⚠️ modscan error (non-fatal): {e}")
        return []

    modules = []
    for line in clean_vol_output(result.stdout):
        if not line.strip() or "Offset" in line or "---" in line or "Volatility" in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            modules.append({"base": parts[0], "name": parts[-1]})
    return modules


def build_module_cross_view(processes: List[Dict[str, Any]],
                             modscan_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare modscan-found module names against every process's PEB module list."""
    if not modscan_entries:
        return {"scan_performed": False, "note": "windows.modscan unavailable or failed",
                "hidden_modules_detected": 0, "modscan_only": []}

    known_names = set()
    for proc in processes:
        for m in proc.get("modules", []):
            name = (m.get("name") or m.get("Name") or "") if isinstance(m, dict) else str(m)
            if name:
                known_names.add(name.lower())

    hidden = [m for m in modscan_entries if m["name"].lower() not in known_names]
    return {
        "scan_performed": True,
        "modscan_count": len(modscan_entries),
        "hidden_modules_detected": len(hidden),
        "modscan_only": hidden[:200],  # cap to keep output size sane
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
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit VAD/thread extraction to first N processes, "
                             "0=all (default). WARNING: any nonzero value silently "
                             "skips VAD/thread extraction for all processes beyond "
                             "the limit — this previously caused real infections to "
                             "be missed entirely when the malware process wasn't "
                             "among the first N by PID order.")

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

        # Environment variables (proxy/PATH/temp-dir tampering)
        envars_by_pid = extract_all_envars(memory_path)
        print(f"✓ Extracted environment variables for {len(envars_by_pid)} processes")

        # ========== PERSISTENCE MECHANISM DETECTION (additive) ==========
        print("🔒 Checking registry Run/RunOnce keys for persistence (T1547.001)...")
        registry_persistence = extract_registry_persistence(memory_path)
        print(f"✓ Found {len(registry_persistence)} registry auto-start entr{'y' if len(registry_persistence)==1 else 'ies'}")

        print("🔒 Scanning services for persistence (T1543.003)...")
        service_persistence = extract_service_persistence(memory_path)
        n_flagged = len(service_persistence.get("flagged_services", [])) if service_persistence else 0
        print(f"✓ Scanned {service_persistence.get('total_services_scanned', 0) if service_persistence else 0} "
              f"services, {n_flagged} flagged as suspicious")

        # ========== FILE ARTIFACT EXTRACTION (additive) ==========
        print("📂 Scanning for forensic file artifacts (browser data, archives, screenshots)...")
        file_artifacts = extract_file_artifacts(memory_path)
        print(f"✓ Found {len(file_artifacts)} forensic file artifacts")

        # ========== CROSS-VIEW HIDDEN PROCESS DETECTION (additive) ==========
        psscan_entries = extract_processes_psscan(memory_path)
        cross_view = build_cross_view_analysis(processes, psscan_entries)
        if cross_view["scan_performed"]:
            print(f"✓ Cross-view analysis: {cross_view['hidden_processes_detected']} hidden process(es) detected")
        else:
            print("⚠️ Cross-view analysis skipped (psscan unavailable)")

        modscan_entries = extract_modules_modscan(memory_path)

        # Add parent image names
        enrich_process_relationships(processes)

        # Add command lines and module info (with cmdline analysis)
        enrich_processes_with_cmdlines(processes, cmdlines_by_pid)
        enrich_processes_with_modules(processes, modules_by_pid)

        # Module cross-view must run AFTER enrich_processes_with_modules, since
        # it compares modscan results against each process's enriched module list.
        module_cross_view = build_module_cross_view(processes, modscan_entries)
        if module_cross_view["scan_performed"]:
            print(f"✓ Module cross-view: {module_cross_view['hidden_modules_detected']} hidden module(s) detected")
        else:
            print("⚠️ Module cross-view skipped (modscan unavailable)")

        # NEW: Enrich with security context, handles, and network
        for proc in processes:
            pid = proc["pid"]
            enrich_process_with_security_context(proc, sids_by_pid)
            enrich_process_with_handle_analysis(proc, handles_by_pid)
            enrich_process_with_network(proc, connections_by_pid)
            enrich_process_with_envars(proc, envars_by_pid)

        # Extract VADs and assign threads
        process_limit = args.limit if args.limit > 0 else len(processes)
        if args.limit > 0 and args.limit < len(processes):
            print(f"⚠️⚠️⚠️ --limit {args.limit} set: only the first {args.limit}/{len(processes)} "
                  f"processes will get VAD/thread extraction. {len(processes) - args.limit} "
                  f"process(es) will have empty vads/threads and CANNOT be flagged for "
                  f"injection, no matter what they actually contain. Use --limit 0 for a "
                  f"real investigation.")
        for proc in processes[:process_limit]:
            pid = proc["pid"]

            try:
                print(f" 📊 Extracting VADs for PID {pid}...", end='')
                proc["vads"] = extract_vads_for_process(memory_path, pid)
                proc["threads"] = threads_by_pid.get(pid, [])
                proc["vad_anomalies"] = detect_vad_tree_anomalies(proc["vads"])
                anomaly_note = f", {proc['vad_anomalies']['total_anomalies']} VAD anomalies" \
                    if proc["vad_anomalies"]["total_anomalies"] else ""
                print(f" {len(proc['vads'])} VADs, {len(proc['threads'])} threads{anomaly_note}")
            except Exception as e:
                print(f" ⚠️ Error: {e}")
                if "vads" not in proc:
                    proc["vads"] = []
                if "threads" not in proc:
                    proc["threads"] = []
                if "vad_anomalies" not in proc:
                    proc["vad_anomalies"] = {"unmapped_image_vads": [], "overlapping_vad_ranges": [],
                                              "guard_page_sandwiching": [], "total_anomalies": 0}

        # Initialize defaults for skipped processes (fix downstream KeyError)
        for proc in processes[process_limit:]:
            if "vads" not in proc:
                proc["vads"] = []
            if "threads" not in proc:
                proc["threads"] = []
            if "vad_anomalies" not in proc:
                proc["vad_anomalies"] = {"unmapped_image_vads": [], "overlapping_vad_ranges": [],
                                          "guard_page_sandwiching": [], "total_anomalies": 0}

        # Byte-level analysis (entropy/PE/strings/XOR/RC4/RedLine-config) —
        # moved here from Engine 3 as part of the pipeline architecture fix:
        # raw memory-file access happens ONLY in Engine 2. Also fixes the
        # actual hang this replaced: batched once per PID instead of once
        # per region (see enrich_private_exec_vads_with_byte_analysis).
        print("\n🔬 Running byte-level analysis on private-exec candidate regions...")
        enrich_private_exec_vads_with_byte_analysis(memory_path, processes[:process_limit])

        print("\n🔐 Extracting process image hashes for candidate PIDs...")
        enrich_processes_with_image_hashes(memory_path, processes[:process_limit])

        print("\n🔎 Running malfind reference scan (whole-dump, once)...")
        malfind_reference_hits = run_malfind_reference_scan(memory_path)

        # Add enrichment status without changing existing structure
        add_enrichment_status(processes, cmdlines_by_pid, modules_by_pid, threads_by_pid)

        # ── Ghost / Dead Process Reconstruction ──────────────────────────────
        # Find PPIDs referenced by living processes that don't appear in the
        # running process list — these are dropper/loader processes that exited
        # before memory capture. Reconstruct what we can from child references.
        live_pids = {p["pid"] for p in processes}
        ghost_map: Dict[int, Dict] = {}
        for proc in processes:
            ppid = proc.get("ppid")
            if ppid and ppid not in live_pids and ppid not in ghost_map and ppid > 4:
                ghost_map[ppid] = {
                    "pid": ppid,
                    "status": "EXITED_BEFORE_CAPTURE",
                    "known_children": [],
                    "forensic_note": (
                        f"PID {ppid} is not in the running process list but is referenced "
                        f"as parent by one or more living processes. This is consistent with "
                        f"a dropper or loader that executed child processes and then exited "
                        f"to reduce its forensic footprint."
                    ),
                }
            if ppid and ppid in ghost_map:
                ghost_map[ppid]["known_children"].append({
                    "pid": proc.get("pid"),
                    "image_name": proc.get("image_name"),
                    "create_time": proc.get("create_time"),
                    "command_line": proc.get("command_line", "N/A"),
                })
        ghost_processes = list(ghost_map.values())

        # ── Chain of Custody Metadata ─────────────────────────────────────────
        import hashlib, datetime as _dt
        coc_meta: Dict[str, Any] = {
            "analysis_timestamp_utc": _dt.datetime.utcnow().isoformat() + "Z",
            "tool": "engine_os_structure_extractor",
            "volatility_profile": "Volatility 3",
            "python_version": sys.version,
            "note": "Hash computed at analysis time over the memory file path as recorded.",
        }
        try:
            mem_path = getattr(args, "memory_file", None) or ""
            if mem_path and Path(mem_path).exists():
                sha256 = hashlib.sha256()
                with open(mem_path, "rb") as mf:
                    for chunk in iter(lambda: mf.read(65536), b""):
                        sha256.update(chunk)
                coc_meta["memory_dump_sha256"] = sha256.hexdigest()
                coc_meta["memory_dump_path"] = str(Path(mem_path).resolve())
                coc_meta["memory_dump_size_bytes"] = Path(mem_path).stat().st_size
        except Exception as _e:
            coc_meta["hash_error"] = str(_e)

        structures = {
            "engine_id": "engine_os_structure_extractor",
            "processes": processes,
            "cross_view_analysis": cross_view,
            "module_cross_view": module_cross_view,
            "ghost_processes": ghost_processes,
            "chain_of_custody": coc_meta,
            "persistence_mechanisms": {
                "registry_run_keys": registry_persistence,
                "services": service_persistence,
                "total_findings": len(registry_persistence) + n_flagged,
            },
            "file_artifacts": file_artifacts,
            "malfind_reference_hits": malfind_reference_hits,
        }

        # Output validation
        if not validate_structures(structures):
            raise ValueError("OS structures validation failed")

        # Save output
        with open(output_path, 'w', encoding='utf-8') as f:
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
        if cross_view["scan_performed"]:
            print(f"📊 Hidden processes (psscan vs pslist): {cross_view['hidden_processes_detected']}")
        print(f"📄 Output: {output_path.absolute()}")

    except KeyboardInterrupt:
        # Ctrl+C anywhere in this run (VAD extraction, byte-analysis, hash
        # extraction, malfind scan — all of it is inside this try block).
        # "except Exception" never catches KeyboardInterrupt (it's not an
        # Exception subclass in Python), so without this handler, interrupting
        # a slow-but-non-critical step used to silently discard everything
        # already gathered — VAD trees, byte-level analysis, real file
        # hashes — with nothing written to disk. Attempt a best-effort
        # partial write instead.
        print("\n⚠️  ENGINE 2 INTERRUPTED (Ctrl+C)", file=sys.stderr)
        if "processes" in locals() and processes:
            partial_output = {
                "engine_id": "engine_os_structure_extractor",
                "interrupted": True,
                "note": ("This run was interrupted by the user (Ctrl+C) before "
                         "completing. Data below reflects whatever was successfully "
                         "gathered up to that point — some processes, VADs, byte-level "
                         "analysis, hashes, or the malfind reference scan may be "
                         "missing or incomplete. Re-run Engine 2 for a complete result."),
                "processes": processes,
                "malfind_reference_hits": locals().get("malfind_reference_hits", []),
            }
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(partial_output, f, indent=2)
                print(f"💾 Partial results saved to {output_path.absolute()} "
                      f"({len(processes)} process(es) gathered before interruption)",
                      file=sys.stderr)
            except Exception as write_err:
                print(f"❌ Could not save partial results: {write_err}", file=sys.stderr)
        else:
            print("   Interrupted before any process data was gathered — nothing to save.",
                  file=sys.stderr)
        sys.exit(130)  # standard exit code for SIGINT

    except Exception as e:
        print(f"❌ ENGINE 2 ABORTED: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
