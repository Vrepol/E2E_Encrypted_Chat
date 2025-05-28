use std::time::{Duration, Instant};

use unicode_segmentation::UnicodeSegmentation;
/// 一次编辑动作的类别（按你需要再细分）
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum OpKind { Insert, Other }

pub struct UndoMgr {
    stack:       Vec<(String, usize)>, // (内容快照, 光标)
    last_save:   Instant,              // 上一次压栈时间
    last_kind:   OpKind,               // 上一次操作类型
    max_depth:   usize,                // 可选：栈深上限
}

impl UndoMgr {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            last_save: Instant::now(),
            last_kind: OpKind::Other,
            max_depth: 200,
        }
    }

    /// 条件压栈：>500 ms 或操作类型变了
    pub fn maybe_push(&mut self,
                  input: &String,
                  cursor: usize,
                  kind: OpKind)
    {
        let elapsed = self.last_save.elapsed();
        if elapsed > Duration::from_millis(500) || kind != self.last_kind {
            self.stack.push((input.clone(), cursor));
            if self.stack.len() > self.max_depth {
                self.stack.remove(0);            // 裁掉最早的
            }
            self.last_save = Instant::now();
            self.last_kind = kind;
        }
    }

    /// 撤销一步
    pub fn undo(&mut self, input: &mut String, cursor: &mut usize) {
        if let Some((prev, pos)) = self.stack.pop() {
            *input  = prev;
            *cursor = pos.min(input.graphemes(true).count());
        }
    }
}