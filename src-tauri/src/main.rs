#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{io::Write, process::{Command, Stdio}};
use tauri::Manager;
use serde_json::Value;

#[tauri::command]
async fn engine(app: tauri::AppHandle, request: Value) -> Result<Value, String> {
    let allowed = ["status", "import", "analyze", "history", "preview_ai", "explain"];
    if !allowed.contains(&request["action"].as_str().unwrap_or("")) {
        return Err("Неизвестное действие".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let data = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&data).map_err(|e| e.to_string())?;
        let dev = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../engine/cli.py");
        let script = if cfg!(debug_assertions) && dev.is_file() { dev } else {
            app.path().resource_dir().map_err(|e| e.to_string())?.join("engine/cli.py")
        };
        let mut command = Command::new("python");
        command.arg(&script).arg("--data-dir").arg(&data)
            .env("PYTHONIOENCODING", "utf-8")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)] {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().map_err(|e| format!("Не удалось запустить Python 3: {e}"))?;
        child.stdin.take().ok_or("Нет stdin")?.write_all(request.to_string().as_bytes()).map_err(|e| e.to_string())?;
        let result = child.wait_with_output().map_err(|e| e.to_string())?;
        let parsed: Value = serde_json::from_slice(&result.stdout).map_err(|_| {
            format!("Движок не вернул JSON: {}", String::from_utf8_lossy(&result.stderr))
        })?;
        if parsed["ok"] == true { Ok(parsed["data"].clone()) }
        else { Err(parsed["error"].as_str().unwrap_or("Ошибка анализа").to_string()) }
    }).await.map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![engine])
        .run(tauri::generate_context!())
        .expect("Failed to start Autoruns Lens");
}
