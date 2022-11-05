#![no_main]

use libfuzzer_sys::fuzz_target;

use blackhole::dns::traits::FromBuffer;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
   let _ = blackhole::dns::packet::Packet::from_buffer(&mut blackhole::dns::packet::ResizableBuffer {
        buffer: data.to_vec(),
        pos: 0,
    });
});
