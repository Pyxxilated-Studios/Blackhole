#![no_main]

use blackhole::dns::traits::FromBuffer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ =
        blackhole::dns::packet::Packet::from_buffer(&mut blackhole::dns::packet::ResizableBuffer {
            buffer: data.to_vec(),
            pos: 0,
        });

    let data = if data.len() < 512 {
        let mut v = vec![0; 0];
        v.extend(data);
        v.extend((0..(512 - data.len())).map(|_| 0));
        v
    } else {
        data[..512].to_vec()
    };
    let _ = blackhole::dns::packet::Packet::from_buffer(&mut blackhole::dns::packet::Buffer {
        buffer: data.try_into().unwrap(),
        pos: 0,
    });
});
