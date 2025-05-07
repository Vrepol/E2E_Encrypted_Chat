use windows::Win32::{
    System::Console::GetConsoleWindow,
    UI::WindowsAndMessaging::{
        FlashWindowEx,
        FLASHWINFO, FLASHW_ALL,
    },
};
pub fn notify() {
    unsafe {
        let hwnd = GetConsoleWindow();
        if hwnd.0 != 0 {
            let mut info = FLASHWINFO {
                cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
                hwnd,
                dwFlags: FLASHW_ALL,
                uCount: 3,
                dwTimeout: 0,
            };
            FlashWindowEx(&mut info);          // 任务栏闪
        }        // 统一级“叮”声
    }
}

