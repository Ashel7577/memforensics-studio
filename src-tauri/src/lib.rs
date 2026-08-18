use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use tauri::{Manager, Emitter};
use std::net::TcpListener;
use std::io::Write;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Windows spawns a console window for every child process by default, so each
/// engine stage — and the `start` shell used to open URLs — flashed a black box
/// over the app. CREATE_NO_WINDOW suppresses it; a no-op everywhere else.
fn quiet(cmd: &mut Command) -> &mut Command {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngineProgress {
    #[serde(rename = "engineNum")]
    pub engine_num: u8,
    pub name: String,
    pub status: String,
    pub percent: u8,
    pub message: String,
    pub metrics: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Artifact {
    pub filename: String,
    #[serde(rename = "engineNum")]
    pub engine_num: u8,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub ready: bool,
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogLine {
    pub id: String,
    pub timestamp: String,
    #[serde(rename = "engineNum")]
    pub engine_num: Option<u8>,
    pub text: String,
    pub level: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PipelineRun {
    pub id: String,
    pub filename: String,
    pub engines: Vec<u8>,
    pub status: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    pub duration: u64,
}

#[derive(Clone, Debug)]
pub struct PipelineState {
    pub status: String,
    pub engines: Vec<EngineProgress>,
    pub artifacts: Vec<Artifact>,
    pub logs: Vec<LogLine>,
    pub output_dir: String,
}

struct AppState {
    pipelines: Arc<Mutex<HashMap<String, PipelineState>>>,
}

fn engine_names() -> Vec<&'static str> {
    vec![
        "Memory Acquisition",
        "OS Structure Extractor",
        "Private Exec Regions",
        "Execution Evidence",
        "Execution Timeline",
        "Injection Classifier",
        "Forensic Report Generator",
    ]
}

fn make_engine_progress(num: u8, status: &str) -> EngineProgress {
    EngineProgress {
        engine_num: num,
        name: engine_names()[(num - 1) as usize].to_string(),
        status: status.to_string(),
        percent: 0,
        message: String::new(),
        metrics: String::new(),
        error: None,
    }
}

#[tauri::command]
async fn open_file_dialog(app: tauri::AppHandle) -> Result<String, String> {
    // Was osascript, which only exists on macOS — on Windows the spawn failed
    // and the picker silently never opened. The dialog plugin is native on
    // every platform. Safe to block here: async commands run off the main
    // thread, which is the one restriction blocking_pick_file has.
    use tauri_plugin_dialog::DialogExt;

    let picked = app
        .dialog()
        .file()
        .set_title("Select memory dump file")
        .add_filter("Memory images", &["mem", "raw", "dmp", "vmem", "bin", "img"])
        .add_filter("All files", &["*"])
        .blocking_pick_file();

    match picked {
        Some(p) => p
            .into_path()
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|e| e.to_string()),
        None => Err("No file selected".to_string()),
    }
}

/// Path of the run-metadata sidecar inside a job directory.
///
/// History has to survive a restart, and the job registry only lives in memory,
/// so every run records itself next to its artifacts. `get_history` rebuilds the
/// list by reading these back.
fn meta_path(output_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(output_dir).join("job_meta.json")
}

fn write_run_meta(output_dir: &str, run: &PipelineRun) {
    if let Ok(json) = serde_json::to_string_pretty(run) {
        let _ = std::fs::write(meta_path(output_dir), json);
    }
}

fn update_run_meta(output_dir: &str, status: &str, duration: u64) {
    let path = meta_path(output_dir);
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(mut run) = serde_json::from_str::<PipelineRun>(&content) {
            run.status = status.to_string();
            run.duration = duration;
            write_run_meta(output_dir, &run);
        }
    }
}

#[tauri::command]
async fn start_pipeline(
    app: tauri::AppHandle,
    file_path: String,
    engines: Vec<u8>,
    options: serde_json::Value,
) -> Result<String, String> {
    let job_id = format!("job_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let output_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(&job_id);
    std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let output_dir_str = output_dir.to_str().unwrap().to_string();

    let engines_dir = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("engines");

    let limit = options.get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .to_string();

    let state = app.state::<AppState>();
    {
        let mut map = state.pipelines.lock().unwrap();
        let engine_list: Vec<EngineProgress> = (1u8..=7).map(|n| {
            if engines.contains(&n) {
                make_engine_progress(n, "pending")
            } else {
                make_engine_progress(n, "skipped")
            }
        }).collect();
        map.insert(job_id.clone(), PipelineState {
            status: "running".to_string(),
            engines: engine_list,
            artifacts: vec![],
            logs: vec![],
            output_dir: output_dir_str.clone(),
        });
    }

    let filename = std::path::Path::new(&file_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.clone());
    write_run_meta(&output_dir_str, &PipelineRun {
        id: job_id.clone(),
        filename,
        engines: engines.clone(),
        status: "running".to_string(),
        started_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        duration: 0,
    });

    let job_id_clone = job_id.clone();
    let pipelines = state.pipelines.clone();
    let engines_clone = engines.clone();

    std::thread::spawn(move || {
        let e = engines_dir.to_str().unwrap().to_string();
        let o = output_dir_str.clone();
        let d = file_path.clone();

        let started = std::time::Instant::now();
        let mut log_counter = 0u64;

        let mut store_log = |pipelines: &Arc<Mutex<HashMap<String, PipelineState>>>,
                         job_id: &str,
                         engine_num: u8,
                         text: &str,
                         level: &str| {
            log_counter += 1;
            let log = LogLine {
                id: log_counter.to_string(),
                timestamp: format!("{}", log_counter),
                engine_num: Some(engine_num),
                text: text.to_string(),
                level: level.to_string(),
            };
            let mut map = pipelines.lock().unwrap();
            if let Some(pipeline) = map.get_mut(job_id) {
                pipeline.logs.push(log);
            }
        };

        let set_engine_status = |pipelines: &Arc<Mutex<HashMap<String, PipelineState>>>,
                                  job_id: &str,
                                  num: u8,
                                  status: &str,
                                  error: Option<String>| {
            let mut map = pipelines.lock().unwrap();
            if let Some(pipeline) = map.get_mut(job_id) {
                if let Some(eng) = pipeline.engines.iter_mut().find(|e| e.engine_num == num) {
                    eng.status = status.to_string();
                    eng.error = error;
                    if status == "done" { eng.percent = 100; }
                    if status == "running" && eng.percent == 0 { eng.percent = 3; }
                }
            }
        };

        let set_engine_progress = |pipelines: &Arc<Mutex<HashMap<String, PipelineState>>>,
                                    job_id: &str,
                                    num: u8,
                                    percent: u8,
                                    message: &str| {
            let mut map = pipelines.lock().unwrap();
            if let Some(pipeline) = map.get_mut(job_id) {
                if let Some(eng) = pipeline.engines.iter_mut().find(|e| e.engine_num == num) {
                    eng.percent = percent.max(eng.percent).min(99);
                    eng.message = message.to_string();
                }
            }
        };

        // Extracts the trailing integer from a line like "... Found 42 processes"
        fn trailing_int_before(line: &str, marker: &str) -> Option<u32> {
            let idx = line.find(marker)?;
            let prefix = &line[..idx];
            prefix.split_whitespace().last()?.parse::<u32>().ok()
        }

        let add_artifact = |pipelines: &Arc<Mutex<HashMap<String, PipelineState>>>,
                             job_id: &str,
                             filename: &str,
                             engine_num: u8,
                             path: &str| {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let artifact = Artifact {
                filename: filename.to_string(),
                engine_num,
                size_bytes: size,
                ready: true,
                path: path.to_string(),
            };
            let mut map = pipelines.lock().unwrap();
            if let Some(pipeline) = map.get_mut(job_id) {
                pipeline.artifacts.push(artifact);
            }
        };

        let bin = if cfg!(windows) { format!("{}\\memforensics_engine.exe", e) } else { format!("{}/memforensics_engine", e) };
        let engine_configs: Vec<(u8, Vec<String>, &str)> = vec![
            (1, vec![
                "1".into(),
                d.clone(),
                "--method".into(), "VM snapshot".into(),
                "--output".into(), format!("{}/01_memory_evidence.json", o),
            ], "01_memory_evidence.json"),
            (2, vec![
                "2".into(),
                format!("{}/01_memory_evidence.json", o),
                d.clone(),
                "--output".into(), format!("{}/02_os_structures.json", o),
                "--limit".into(), limit.clone(),
            ], "02_os_structures.json"),
            (3, vec![
                "3".into(),
                format!("{}/02_os_structures.json", o),
                "--output".into(), format!("{}/03_private_exec_regions.json", o),
            ], "03_private_exec_regions.json"),
            (4, vec![
                "4".into(),
                format!("{}/02_os_structures.json", o),
                format!("{}/03_private_exec_regions.json", o),
                "--output".into(), format!("{}/04_execution_evidence.json", o),
            ], "04_execution_evidence.json"),
            (5, vec![
                "5".into(),
                format!("{}/04_execution_evidence.json", o),
                "--os-structures".into(), format!("{}/02_os_structures.json", o),
                "--output".into(), format!("{}/05_execution_timeline.json", o),
            ], "05_execution_timeline.json"),
            (6, vec![
                "6".into(),
                format!("{}/05_execution_timeline.json", o),
                format!("{}/03_private_exec_regions.json", o),
                "--os-structures".into(), format!("{}/02_os_structures.json", o),
                "--output".into(), format!("{}/06_classification.json", o),
            ], "06_classification.json"),
            (7, vec![
                "7".into(),
                format!("{}/06_classification.json", o),
                "--timeline".into(), format!("{}/05_execution_timeline.json", o),
                "--os-structures".into(), format!("{}/02_os_structures.json", o),
                "--memory-evidence".into(), format!("{}/01_memory_evidence.json", o),
                "--execution-evidence".into(), format!("{}/04_execution_evidence.json", o),
                "--private-exec-regions".into(), format!("{}/03_private_exec_regions.json", o),
                "--output".into(), format!("{}/07_forensic_report.pdf", o),
            ], "07_forensic_report.pdf"),
        ];

        let mut pipeline_failed = false;

        for (engine_num, args, output_filename) in engine_configs {
            if !engines_clone.contains(&engine_num) {
                continue;
            }
            if pipeline_failed {
                break;
            }

            set_engine_status(&pipelines, &job_id_clone, engine_num, "running", None);
            store_log(&pipelines, &job_id_clone, engine_num,
                &format!("[ENGINE {}] Starting {}...", engine_num, engine_names()[(engine_num-1) as usize]),
                "info");

            let mut child = match quiet(&mut Command::new(&bin))
                .args(&args)
                // Python block-buffers stdout when it is a pipe rather than a TTY, so
                // progress lines sat in an 8KB buffer until the stage ended — long
                // stages (Engine 2) looked frozen and sub-progress parsing was starved.
                // Force line-flushing so output reaches the console as it happens.
                .env("PYTHONUNBUFFERED", "1")
                // Windows consoles default to a legacy codepage (cp1252), which
                // cannot encode the emoji status markers the engines print — the
                // first such line raised UnicodeEncodeError and killed the stage.
                .env("PYTHONIOENCODING", "utf-8:replace")
                .env("PYTHONUTF8", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        let err = format!("Failed to spawn engine {}: {}", engine_num, e);
                        store_log(&pipelines, &job_id_clone, engine_num, &err, "error");
                        set_engine_status(&pipelines, &job_id_clone, engine_num, "failed", Some(err));
                        pipeline_failed = true;
                        continue;
                    }
                };

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut total_items: Option<u32> = None;
                let mut item_count: u32 = 0;
                // 0 means "no cap — walk every process".
                let limit_num: u32 = limit.parse().unwrap_or(0);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        let level = if line.contains("ERROR") || line.contains("❌") {
                            "error"
                        } else if line.contains("✅") || line.contains("COMPLETE") {
                            "success"
                        } else if line.contains("WARNING") {
                            "warning"
                        } else {
                            "info"
                        };
                        store_log(&pipelines, &job_id_clone, engine_num, &line, level);

                        // Real sub-progress: engines print "Found N processes" up front, then
                        // one line per item as they work through the list (e.g. Engine 2's
                        // "Extracting VADs for PID <pid>..."). Derive an actual i/N percentage
                        // from that instead of leaving the bar frozen for the whole stage.
                        // Only the engine's up-front census ("Found N processes") is a
                        // valid denominator. Per-phase summaries such as "Extracted
                        // command lines for 55 processes" also end in "processes" but
                        // count a subset, so accepting them shrank the total below the
                        // running count and produced nonsense like "65/51".
                        if total_items.is_none() && line.contains("Found") {
                            if let Some(n) = trailing_int_before(&line, "processes") {
                                if n > 0 { total_items = Some(n); }
                            }
                        }
                        if engine_num == 2 {
                            // Engine 2 runs a fixed sequence of Volatility passes and
                            // *then* a per-process VAD walk, so its percentage is split
                            // into bands that follow that real execution order: the
                            // survey passes finish by ~45%, the per-process walk (the
                            // longest part) spans 48-88%, and the closing analyses take
                            // it to 97%. Progress is monotonic, so a later phase must
                            // never map lower than an earlier one.
                            let survey: Option<(u8, &str)> = if line.contains("windows.pslist") {
                                Some((6, "Enumerating process list (windows.pslist)"))
                            } else if line.contains("Extracting all threads") {
                                Some((10, "Walking thread structures"))
                            } else if line.contains("windows.cmdline") {
                                Some((14, "Recovering process command lines"))
                            } else if line.contains("windows.dlllist") {
                                Some((18, "Enumerating loaded modules"))
                            } else if line.contains("windows.getsids") {
                                Some((22, "Resolving user SIDs"))
                            } else if line.contains("windows.handles") {
                                Some((26, "Reading handle tables"))
                            } else if line.contains("windows.netscan") || line.contains("windows.netstat") {
                                Some((30, "Scanning network connections"))
                            } else if line.contains("windows.envars") {
                                Some((34, "Extracting environment variables"))
                            } else if line.contains("Run/RunOnce") {
                                Some((38, "Checking registry persistence (T1547.001)"))
                            } else if line.contains("Scanning services") {
                                Some((41, "Scanning services for persistence (T1543.003)"))
                            } else if line.contains("windows.filescan") {
                                Some((44, "Carving forensic file artifacts"))
                            } else {
                                None
                            };

                            if line.contains("Extracting VADs for PID") {
                                // One line per process. The engine only walks the first
                                // `--limit` processes (0 means all), so that — not the
                                // total process count — is the real denominator.
                                item_count += 1;
                                let walked = match (total_items, limit_num) {
                                    (Some(found), 0) => found,
                                    (Some(found), lim) => lim.min(found),
                                    (None, 0) => item_count,
                                    (None, lim) => lim,
                                };
                                let done = item_count.min(walked.max(1));
                                let pct = 48 + ((done as f32 / walked.max(1) as f32) * 40.0) as u8;
                                let msg = format!(
                                    "Walking VAD trees — process {}/{} ({})",
                                    done,
                                    walked,
                                    line.trim()
                                );
                                set_engine_progress(&pipelines, &job_id_clone, engine_num, pct, &msg);
                            } else if line.contains("Running byte-level analysis") {
                                set_engine_progress(&pipelines, &job_id_clone, engine_num, 90,
                                    "Running byte-level entropy/PE analysis...");
                            } else if line.contains("Extracting process image hashes") {
                                set_engine_progress(&pipelines, &job_id_clone, engine_num, 94,
                                    "Hashing process images...");
                            } else if line.contains("Running malfind") {
                                set_engine_progress(&pipelines, &job_id_clone, engine_num, 97,
                                    "Cross-referencing malfind signatures...");
                            } else if let Some((pct, msg)) = survey {
                                set_engine_progress(&pipelines, &job_id_clone, engine_num, pct, msg);
                            }
                        } else if line.contains("Extracting VADs for PID")
                            || line.contains("Extracting threads")
                            || line.contains("Processing PID")
                        {
                            item_count += 1;
                            let done = match total_items {
                                Some(t) => item_count.min(t),
                                None => item_count,
                            };
                            let pct = match total_items {
                                Some(t) if t > 0 => 5 + ((done as f32 / t as f32) * 85.0) as u8,
                                _ => 50,
                            };
                            let msg = match total_items {
                                Some(t) => format!("Processing {}/{} — {}", done, t, line.trim()),
                                None => line.trim().to_string(),
                            };
                            set_engine_progress(&pipelines, &job_id_clone, engine_num, pct, &msg);
                        } else if line.contains("Running byte-level analysis") {
                            set_engine_progress(&pipelines, &job_id_clone, engine_num, 92, "Running byte-level entropy/PE analysis...");
                        } else if line.contains("Extracting process image hashes") {
                            set_engine_progress(&pipelines, &job_id_clone, engine_num, 95, "Hashing process images...");
                        } else if line.contains("Running malfind") {
                            set_engine_progress(&pipelines, &job_id_clone, engine_num, 97, "Cross-referencing malfind signatures...");
                        } else if line.starts_with("📊") || line.starts_with("🔬")
                            || line.starts_with("🔐") || line.starts_with("🔎")
                            || line.starts_with("🚀")
                        {
                            set_engine_progress(&pipelines, &job_id_clone, engine_num, 8, line.trim_start_matches(|c: char| !c.is_alphanumeric()).trim());
                        }
                    }
                }
            }

            let result = child.wait_with_output().map_err(|e| e.to_string());
            match result {
                Ok(out) if out.status.success() => {
                    let output_path = format!("{}/{}", o, output_filename);
                    add_artifact(&pipelines, &job_id_clone, output_filename, engine_num, &output_path);
                    set_engine_status(&pipelines, &job_id_clone, engine_num, "done", None);
                    store_log(&pipelines, &job_id_clone, engine_num,
                        &format!("[ENGINE {}] ✅ Complete -> {}", engine_num, output_filename),
                        "success");
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    store_log(&pipelines, &job_id_clone, engine_num, &stderr, "error");
                    set_engine_status(&pipelines, &job_id_clone, engine_num, "failed", Some(stderr));
                    pipeline_failed = true;
                }
                Err(e) => {
                    set_engine_status(&pipelines, &job_id_clone, engine_num, "failed", Some(e.clone()));
                    store_log(&pipelines, &job_id_clone, engine_num, &e, "error");
                    pipeline_failed = true;
                }
            }
        }

        let final_status = if pipeline_failed { "failed" } else { "done" };
        update_run_meta(&o, final_status, started.elapsed().as_secs());
        let mut map = pipelines.lock().unwrap();
        if let Some(pipeline) = map.get_mut(&job_id_clone) {
            pipeline.status = final_status.to_string();
        }
    });

    Ok(job_id)
}

#[tauri::command]
async fn get_pipeline_status(app: tauri::AppHandle, job_id: String) -> Result<String, String> {
    let state = app.state::<AppState>();
    let map = state.pipelines.lock().unwrap();
    Ok(map.get(&job_id).map(|p| p.status.clone()).unwrap_or("unknown".to_string()))
}

#[tauri::command]
async fn get_engine_progress(app: tauri::AppHandle, job_id: String) -> Result<Vec<EngineProgress>, String> {
    let state = app.state::<AppState>();
    let map = state.pipelines.lock().unwrap();
    Ok(map.get(&job_id).map(|p| p.engines.clone()).unwrap_or_default())
}

#[tauri::command]
async fn get_artifacts(app: tauri::AppHandle, job_id: String) -> Result<Vec<Artifact>, String> {
    let state = app.state::<AppState>();
    let map = state.pipelines.lock().unwrap();
    Ok(map.get(&job_id).map(|p| p.artifacts.clone()).unwrap_or_default())
}

#[tauri::command]
async fn get_logs(app: tauri::AppHandle, job_id: String, since: usize) -> Result<Vec<LogLine>, String> {
    let state = app.state::<AppState>();
    let map = state.pipelines.lock().unwrap();
    Ok(map.get(&job_id)
        .map(|p| p.logs[since.min(p.logs.len())..].to_vec())
        .unwrap_or_default())
}

#[tauri::command]
async fn download_artifact(app: tauri::AppHandle, job_id: String, filename: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let path = {
        let map = state.pipelines.lock().unwrap();
        map.get(&job_id)
            .and_then(|p| p.artifacts.iter().find(|a| a.filename == filename))
            .map(|a| a.path.clone())
    };
    if let Some(path) = path {
        // `open` is macOS-only — on Windows this command silently failed to
        // spawn, so "reveal artifact" did nothing at all there.
        #[cfg(target_os = "macos")]
        let mut cmd = { let mut c = Command::new("open"); c.args(["--reveal"]); c.arg(&path); c };
        #[cfg(target_os = "windows")]
        let mut cmd = {
            // Explorer only understands backslash-separated paths here; the job
            // paths are built with forward slashes and `/select,` silently opens
            // the user's Documents folder instead unless they are normalised.
            let mut c = Command::new("explorer");
            c.arg(format!("/select,{}", path.replace('/', "\\")));
            quiet(&mut c);
            c
        };
        #[cfg(all(unix, not(target_os = "macos")))]
        let mut cmd = {
            let parent = std::path::Path::new(&path).parent()
                .map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
            let mut c = Command::new("xdg-open"); c.arg(parent); c
        };
        cmd.spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn open_file(path: String) -> Result<(), String> {
    // Same story as download_artifact: opening the generated PDF report only
    // ever worked on macOS.
    #[cfg(target_os = "macos")]
    let mut cmd = { let mut c = Command::new("open"); c.arg(&path); c };
    #[cfg(target_os = "windows")]
    let mut cmd = { let mut c = Command::new("cmd"); c.args(["/C", "start", "", &path]); quiet(&mut c); c };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = { let mut c = Command::new("xdg-open"); c.arg(&path); c };
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}

/// Past runs, newest first.
///
/// Rebuilt from the `job_meta.json` sidecar each run writes into its own output
/// directory, so history survives a restart even though the job registry itself
/// is in-memory only. A directory left behind by a run that was killed mid-flight
/// still reads as "running"; it is reported as failed rather than shown as if it
/// were still live, since nothing is driving it any more.
#[tauri::command]
async fn get_history(app: tauri::AppHandle) -> Result<Vec<PipelineRun>, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    if !dir.exists() {
        return Ok(vec![]);
    }

    let live: Vec<String> = {
        let state = app.state::<AppState>();
        let map = state.pipelines.lock().unwrap();
        map.iter()
            .filter(|(_, p)| p.status == "running")
            .map(|(id, _)| id.clone())
            .collect()
    };

    let mut runs: Vec<PipelineRun> = vec![];
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let content = match std::fs::read_to_string(entry.path().join("job_meta.json")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(mut run) = serde_json::from_str::<PipelineRun>(&content) {
            if run.status == "running" && !live.contains(&run.id) {
                run.status = "failed".to_string();
            }
            runs.push(run);
        }
    }

    // Job ids are `job_<unix-millis>`, so a plain descending sort is chronological.
    runs.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(runs)
}

/// Delete a run: its artifacts, its metadata and its registry entry.
#[tauri::command]
async fn delete_job(app: tauri::AppHandle, job_id: String) -> Result<(), String> {
    // Never let a caller-supplied id escape the app data directory.
    if job_id.is_empty()
        || !job_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Invalid job id".to_string());
    }

    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(&job_id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }

    let state = app.state::<AppState>();
    let mut map = state.pipelines.lock().unwrap();
    map.remove(&job_id);
    Ok(())
}

#[tauri::command]
async fn get_output_dir(app: tauri::AppHandle) -> Result<String, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.to_str().unwrap().to_string())
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            pipelines: Arc::new(Mutex::new(HashMap::new())),
        })
        .setup(|app| {
            /* The window is created hidden so the compositor never shows an
             * empty bright frame. Reveal it on a timer as a guaranteed floor —
             * the frontend calls show_main_window as soon as it has painted,
             * which usually lands first, but the window must never be able to
             * stay hidden if that call does not arrive. */
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(600));
                if let Some(win) = handle.get_webview_window("main") {
                    if !win.is_visible().unwrap_or(true) {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
            });
            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_log::Builder::new().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            open_file_dialog,
            start_pipeline,
            get_pipeline_status,
            get_engine_progress,
            get_artifacts,
            get_logs,
            download_artifact,
            open_file,
            get_output_dir,
            get_history,
            delete_job,
            get_report_pdf_path,
            get_report_metadata,
            read_file,
            open_url,
            show_main_window,
            start_oauth_listener,
            get_pdf_base64,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn get_report_pdf_path(app: tauri::AppHandle, job_id: String) -> Result<String, String> {
    let state = app.state::<AppState>();
    let map = state.pipelines.lock().unwrap();
    map.get(&job_id)
        .and_then(|p| p.artifacts.iter().find(|a| a.filename.ends_with(".pdf")))
        .map(|a| a.path.clone())
        .ok_or("PDF not found".to_string())
}

#[tauri::command]
async fn get_report_metadata(app: tauri::AppHandle, job_id: String) -> Result<serde_json::Value, String> {
    let state = app.state::<AppState>();
    let output_dir = {
        let map = state.pipelines.lock().unwrap();
        map.get(&job_id).map(|p| p.output_dir.clone()).ok_or("Job not found".to_string())?
    };
    let classification_path = format!("{}/06_classification.json", output_dir);
    let content = std::fs::read_to_string(&classification_path).map_err(|e| e.to_string())?;
    let data: serde_json::Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(data)
}


#[tauri::command]
async fn get_pdf_base64(app: tauri::AppHandle, job_id: String) -> Result<String, String> {
    use base64::{Engine as _, engine::general_purpose};
    let state = app.state::<AppState>();
    let path = {
        let map = state.pipelines.lock().unwrap();
        map.get(&job_id)
            .and_then(|p| p.artifacts.iter().find(|a| a.filename.ends_with(".pdf")))
            .map(|a| a.path.clone())
            .ok_or("PDF not found".to_string())?
    };
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    Ok(general_purpose::STANDARD.encode(&bytes))
}

#[tauri::command]
async fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}


/// Reveal the window once the frontend has painted its first frame.
///
/// The window is created hidden (see tauri.conf.json) because the native window
/// is composited before the webview has any content, which shows as a bright
/// flash on launch. The frontend calls this as soon as it has rendered.
#[tauri::command]
async fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("main") {
        win.show().map_err(|e| e.to_string())?;
        let _ = win.set_focus();
    }
    Ok(())
}

/// Start a one-shot loopback listener for the OAuth redirect.
///
/// Google refuses OAuth inside embedded webviews, so sign-in has to happen in
/// the user's real browser. The browser is sent back to http://127.0.0.1:<port>
/// with the authorization code, which this listener captures and forwards to
/// the frontend as an `oauth-callback` event. Returns the bound port so the
/// caller can build a matching redirect URL.
#[tauri::command]
async fn start_oauth_listener(app: tauri::AppHandle) -> Result<u16, String> {
    // Fixed candidates: the redirect URL has to be registered with the auth
    // provider ahead of time, so the port cannot be arbitrary.
    let listener = [1421u16, 1422, 1423, 1424]
        .iter()
        .find_map(|p| TcpListener::bind(("127.0.0.1", *p)).ok())
        .ok_or_else(|| "no free loopback port in 1421-1424".to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    std::thread::spawn(move || {
        // A single request is all we need; the listener drops afterwards.
        if let Ok((mut stream, _)) = listener.accept() {
            let mut reader = BufReader::new(match stream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            });
            let mut line = String::new();
            let _ = reader.read_line(&mut line);

            // "GET /?code=... HTTP/1.1"
            let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut code = String::new();
            let mut err = String::new();
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("code", v)) => code = v.to_string(),
                    Some(("error", v)) => err = v.to_string(),
                    Some(("error_description", v)) if err.is_empty() => err = v.to_string(),
                    _ => {}
                }
            }

            let body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>MemForensics Studio</title></head>\
<body style=\"background:#04060c;color:#cfe3f5;font-family:-apple-system,Segoe UI,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0\">\
<div style=\"text-align:center\"><div style=\"font-size:15px;letter-spacing:.04em\">Signed in.</div>\
<div style=\"font-size:12px;opacity:.55;margin-top:8px\">You can close this tab and return to MemForensics Studio.</div></div></body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();

            let payload = if code.is_empty() {
                serde_json::json!({ "error": if err.is_empty() { "no authorization code returned".into() } else { err } })
            } else {
                serde_json::json!({ "code": code })
            };
            let _ = app.emit("oauth-callback", payload);
        }
    });

    Ok(port)
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut cmd = { let mut c = Command::new("open"); c.arg(&url); c };
    #[cfg(target_os = "windows")]
    let mut cmd = { let mut c = Command::new("cmd"); c.args(["/C", "start", "", &url]); quiet(&mut c); c };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = { let mut c = Command::new("xdg-open"); c.arg(&url); c };

    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}
