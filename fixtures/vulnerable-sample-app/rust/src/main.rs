// Intentionally vulnerable Rust sample used by ShipSafe integration tests.
// DO NOT copy any of this into real code.

static mut REQUEST_COUNTER: u32 = 0;

fn reinterpret(x: u32) -> f32 {
    unsafe { std::mem::transmute(x) }
}

fn main() {
    unsafe {
        REQUEST_COUNTER += 1;
    }
    let _ = reinterpret(42);
}
