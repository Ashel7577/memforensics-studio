use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use tauri::Manager;
use serde::{Deserialize, Serialize};

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
    use tauri_plugin_dialog::DialogExt;
    let file = app.dialog().file().blocking_pick_file();
    match file {
        Some(f) => Ok(f.to_string()),
        None => Err("No file selected".to_string()),
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

    let job_id_clone = job_id.clone();
    let pipelines = state.pipelines.clone();
    let engines_clone = engines.clone();

    std::thread::spawn(move || {
        let e = engines_dir.to_str().unwrap().to_string();
        let o = output_dir_str.clone();
        let d = file_path.clone();

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
                    if status == "running" { eng.percent = 50; }
                }
            }
        };

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

        let bin_name = if cfg!(target_os = "windows") { "memforensics_engine.exe" } else { "memforensics_engine" };
        let bin = format!("{}/{}", e, bin_name);
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

            let mut child = match Command::new(&bin)
                .args(&args)
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
        #[cfg(target_os = "macos")]
        Command::new("open").arg("--reveal").arg(&path).spawn().map_err(|e| e.to_string())?;
        #[cfg(target_os = "windows")]
        Command::new("explorer").arg("/select,").arg(&path).spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn open_file(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    Command::new("open").arg(&path).spawn().map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    Command::new("cmd").args(["/C", "start", "", &path]).spawn().map_err(|e| e.to_string())?;
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
            get_report_pdf_path,
            get_report_metadata,
            read_file,
            open_url,
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

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    Command::new("open").arg(&url).spawn().map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    Command::new("cmd").args(["/C", "start", "", &url]).spawn().map_err(|e| e.to_string())?;
    Ok(())
}
