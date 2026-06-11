// Test cases for rules/sast/rust.yml (semgrep --test format).

fn transmute_example(x: u32) -> f32 {
    // ruleid: ai-rust-mem-transmute, ai-rust-unsafe-block
    unsafe { std::mem::transmute(x) }
}

fn safe_bits(x: u32) -> f32 {
    // ok: ai-rust-mem-transmute
    f32::from_bits(x)
}

// ruleid: ai-rust-static-mut
static mut COUNTER: u32 = 0;

// ok: ai-rust-static-mut
static LIMIT: u32 = 10;

fn unsafe_block_example(ptr: *const u8) -> u8 {
    // ruleid: ai-rust-unsafe-block
    unsafe { *ptr }
}

fn spawn_with_unwrap() {
    std::thread::spawn(move || {
        let value: Result<u32, ()> = Ok(1);
        // ruleid: ai-rust-unwrap-in-spawned-thread
        let _ = value.unwrap();
    });
}

fn spawn_handled() {
    // ok: ai-rust-unwrap-in-spawned-thread
    std::thread::spawn(move || {
        let value: Result<u32, ()> = Ok(1);
        if let Ok(v) = value {
            let _ = v;
        }
    });
}
