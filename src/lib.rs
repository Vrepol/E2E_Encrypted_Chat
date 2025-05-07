// lib.rs

pub mod client;

#[cfg(test)]
mod tests {
    // 1) 导入模块
    use crate::client::notifier;
    // 或者直接导入函数
    // use crate::client::notifier::notify;

    #[test]
    fn test_notify() {
        // 如果你用了 `use crate::client::notifier;`：
        notifier::notify();

        // 如果你用了 `use crate::client::notifier::notify;`：
        // notify();
    }
}
