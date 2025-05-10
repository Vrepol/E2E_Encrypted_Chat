// client/notifier.rs
#[cfg(target_os = "windows")]
pub fn notify() {
    use windows::Win32::{
        Foundation::HWND,
        System::Console::GetConsoleWindow,
        UI::WindowsAndMessaging::{
            FlashWindowEx,
            FLASHWINFO, FLASHW_ALL,
        },
    };
    use super::sounds;
        // 任务栏闪烁
        unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd != HWND(0) {
            let mut info = FLASHWINFO {
                cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
                hwnd,
                dwFlags: FLASHW_ALL,
                uCount: 3,
                dwTimeout: 0,
            };
            let _ = FlashWindowEx(&mut info);
        }
    }
    std::thread::spawn(|| {
        sounds::play_async();
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn notify() {
    // ① 终端响铃（ASCII 0x07）。对大多数 TTY / iTerm / GNOME Terminal 都生效
    print!("\x07");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // ② 如果终端静音，可考虑用 libnotify / osascript 等 GUI 通知替代：
    //    #[cfg(target_os = "macos")] {
    //        std::process::Command::new("osascript")
    //            .arg("-e")
    //            .arg("display notification \"新消息\" with title \"Rust‑Chat\" sound name \"Submarine\"")
    //            .spawn()
    //            .ok();
    //    }
}
