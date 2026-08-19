# MemForensics Studio

A desktop application for detecting process-injection malware in Windows memory
images. It runs a seven-stage forensic pipeline over a raw memory dump and
produces a court-style PDF report, machine-readable IOCs, and ready-to-deploy
detection rules.

Built with Tauri (Rust + React), with the analysis engines written in Python on
top of [Volatility 3](https://github.com/volatilityfoundation/volatility3).

![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Download

Grab the latest installer from the
[releases page](https://github.com/Ashel7577/memforensics-studio/releases/latest):

- **macOS** — `MemForensics.Studio_<version>_aarch64.dmg`
- **Windows** — `MemForensics.Studio_<version>_x64_en-US.msi` (or the
  `_x64-setup.exe` NSIS installer)

Everything needed to run an analysis is bundled, including a standalone
Volatility 3 build. There is no separate Python or Volatility install to
manage, and the application performs no network access during analysis.

## What it does

Point it at a `.raw`, `.mem`, or `.dmp` Windows memory image. The pipeline runs
seven stages in order, each consuming the previous stage's JSON output:

| # | Stage | Produces |
|---|-------|----------|
| 1 | Memory acquisition | Validates and hashes the dump, establishing chain of custody |
| 2 | OS structure extraction | Processes, VADs, threads, handles, network connections, and whole-dump string scanning |
| 3 | Private executable memory | Filters to private, non-file-backed executable regions |
| 4 | Execution evidence correlation | Proves execution by intersecting thread start addresses with those regions |
| 5 | Execution flow reconstruction | Builds a chronological timeline of the intrusion |
| 6 | Injection technique classification | Scores ten injection techniques, extracts C2 intelligence, attributes the user |
| 7 | Forensic reporting | Renders the PDF report plus STIX, CSV, and YARA/Sigma exports |

### Output

- **PDF report** — executive summary, attack chain, C2 infrastructure, memory
  protection inventory, MITRE ATT&CK mapping, user attribution, and a
  false-positive rejection matrix
- **IOCs** — STIX 2.1 bundle, CSV, and JSON
- **Detection rules** — YARA rules plus Sigma and Suricata signatures generated
  from what was actually found in the dump

## Design notes

**One-way data flow.** Each engine reads only the upstream JSON it declares.
Raw memory is touched by stages 1 and 2 only; every later stage works from
what stage 2 already extracted. This keeps the expensive memory passes to one
place and makes each stage independently reproducible from its inputs.

**Proof over heuristics in stage 4.** Execution is established mathematically —
a thread's start address either falls inside a private executable region or it
does not. Confidence scoring and weighted heuristics live in stage 6, where
they are labelled as such.

**Fail current, not stale.** A stage that finds nothing still writes a fresh,
valid, empty result rather than aborting, so a downstream stage can never
silently consume a previous run's output as if it were current.

**False-positive filtering.** System processes that legitimately share
memory-mapped regions at common base addresses are whitelisted, and re-included
only when corroborating evidence exists — a C2 connection, a suspicious command
line, or proxied execution.

## Building from source

Requires Node.js 20+, Rust (stable), and Python 3.11+.

```bash
npm install

# Build the bundled engine and Volatility binaries
pip install pyinstaller reportlab volatility3
cd src-tauri/engines
pyinstaller --noconfirm memforensics_engine.spec
cp dist/memforensics_engine ./memforensics_engine && chmod +x ./memforensics_engine
cd vol_bundle && pyinstaller --noconfirm vol_standalone.spec
cp dist/vol_standalone ../vol && chmod +x ../vol
cd ../../..

npm run tauri dev     # run locally
npm run tauri build   # produce installers
```

Releases are cut by pushing a `v*` tag, which builds and publishes both
platforms via GitHub Actions.

## Running the engines directly

The pipeline works standalone, without the desktop app:

```bash
cd src-tauri/engines
python3 engine_memory_acquisition.py memory.raw --method "VM snapshot" --output 01_memory_evidence.json
python3 engine_os_structure_extractor.py 01_memory_evidence.json memory.raw --output 02_os_structures.json
python3 engine_private_exec_memory_analyzer.py 02_os_structures.json --output 03_private_exec_regions.json
python3 engine_execution_evidence_correlator.py 02_os_structures.json 03_private_exec_regions.json --output 04_execution_evidence.json
python3 engine_execution_flow_reconstructor.py 04_execution_evidence.json --os-structures 02_os_structures.json --output 05_execution_timeline.json
python3 engine_injection_technique_classifier.py 05_execution_timeline.json 03_private_exec_regions.json --os-structures 02_os_structures.json --output 06_classification.json
python3 engine_forensic_reporting.py 06_classification.json --timeline 05_execution_timeline.json --os-structures 02_os_structures.json --memory-evidence 01_memory_evidence.json --execution-evidence 04_execution_evidence.json --private-exec-regions 03_private_exec_regions.json --output 07_forensic_report.pdf
```

Stage 2 requires `vol` (Volatility 3) on `PATH`, or the bundled binary beside
the engine sources.

## License

MIT — see [LICENSE](LICENSE).
