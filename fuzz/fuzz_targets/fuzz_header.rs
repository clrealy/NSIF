#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The contract: Ok or a typed Error, never a panic.
    let _ = nsif_format::fuzz::header(data);
});
