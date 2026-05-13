#[cfg(windows)]
fn main() {
    winresource::WindowsResource::new()
        .set_icon("assets/icon.ico")
        .set("ProductName", "MISTV")
        .set("FileDescription", "MISTV")
        .compile()
        .expect("failed to embed Windows icon");
}

#[cfg(not(windows))]
fn main() {}
