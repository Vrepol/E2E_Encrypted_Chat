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

    unsafe {
        let hwnd = GetConsoleWindow();          // HWND 类型
        // 与 HWND(0) 比较，而不是裸 0
        if hwnd != HWND(0) {
            let mut info = FLASHWINFO {
                cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
                hwnd,
                dwFlags: FLASHW_ALL,
                uCount: 3,
                dwTimeout: 0,
            };
            let _ = FlashWindowEx(&mut info);   // 任务栏闪
        }
    }
}
