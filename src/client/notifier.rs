// src/client/notifier.rs
#[cfg(target_os = "windows")]
pub fn notify() {
    // 让任务栏图标闪烁 3 次，相当于 微信的“消息提醒”
    use windows::Win32::{
        System::Console::GetConsoleWindow,
        UI::WindowsAndMessaging::{FlashWindowEx, FLASHWINFO, FLASHW_ALL},
    };
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_invalid() {
            let mut info = FLASHWINFO::default();
            info.cbSize    = std::mem::size_of::<FLASHWINFO>() as u32;
            info.hwnd      = hwnd;
            info.dwFlags   = FLASHW_ALL;
            info.uCount    = 3;
            info.dwTimeout = 0;
            let _ = FlashWindowEx(&info);
        }
    }
}
