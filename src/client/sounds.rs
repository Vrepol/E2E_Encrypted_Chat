use cpal::traits::*;
use once_cell::sync::Lazy;
use crossbeam_channel::{unbounded, Sender};
use std::{
    f32::consts::PI,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread,
    time::Duration,
};

/// 通道：告诉音频线程“要播放几次 beep”
static BEEP_TX: Lazy<Sender<usize>> = Lazy::new(|| {
    let (tx, rx) = unbounded();
    spawn_audio_thread(rx);
    tx
});
/// 防抖：正在播放中就丢弃新请求
static IS_PLAYING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
/// 剩余要播放的 beep 数量（回调里减，外层读）
static REMAINING: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(0));

/// 外部调用：异步播放 3 次提示音
pub fn play_async() {
    if IS_PLAYING.swap(true, Ordering::AcqRel) {
        return;
    }
    // 先设置剩余次数，再发给回调
    REMAINING.store(3, Ordering::SeqCst);
    let _ = BEEP_TX.send(3);
}

fn spawn_audio_thread(rx: crossbeam_channel::Receiver<usize>) {
    thread::spawn(move || {
        // 1. 打设备、建流
        let host   = cpal::default_host();
        let device = host.default_output_device().expect("no output device");
        let cfg    = device.default_output_config().expect("bad config");
        let sr     = cfg.sample_rate().0 as f32;

        // 2. 回调内部维护自己的队列
        let mut play_queue: Vec<(usize, f32)> = Vec::new();
        let beep_dur  = 0.3;
        let pause_dur = 0.05;
        let cycle     = beep_dur + pause_dur;

        let stream = device.build_output_stream(
            &cfg.into(),
            move |data: &mut [f32], _| {
                // 收新请求
                while let Ok(n) = rx.try_recv() {
                    play_queue.push((n, 0.0));
                }

                for s in data.iter_mut() {
                    if let Some((left, t)) = play_queue.first_mut() {
                        if *left == 0 {
                            play_queue.remove(0);
                            continue;
                        }
                        let pos = *t % cycle;
                        if pos <= beep_dur {
                            let tone = (2.0 * PI * 880.0 * pos).sin() * 0.6
                                     + (2.0 * PI * 1320.0 * pos).sin() * 0.4;
                            let fade = if pos < 0.005 {
                                pos / 0.005
                            } else if pos > beep_dur - 0.005 {
                                (beep_dur - pos) / 0.005
                            } else {
                                1.0
                            };
                            *s = tone * 0.25 * fade;
                        } else {
                            *s = 0.0;
                        }
                        *t += 1.0 / sr;
                        // 周期结束，次数--
                        if *t >= cycle {
                            *left -= 1;
                            *t = 0.0;
                            REMAINING.fetch_sub(1, Ordering::SeqCst);
                        }
                    } else {
                        *s = 0.0;
                    }
                }
            },
            |_| eprintln!("audio error"),
            None,
        ).expect("build_output_stream failed");

        stream.play().expect("play failed");

        // 3. 外层循环：监控剩余任务数，清除防抖
        loop {
            if REMAINING.load(Ordering::SeqCst) == 0 {
                IS_PLAYING.store(false, Ordering::Release);
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
}
