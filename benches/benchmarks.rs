use std::path::Path;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns_server::{
    authority::MessageRequest,
    server::{Protocol, Request},
};

fn filter_parsing(c: &mut Criterion) {
    c.bench_function("parsing a filter list", |b| {
        b.iter(|| {
            black_box(
                blackhole::filter::rules::Rules::parse(Path::new("benches/test.txt")).unwrap(),
            )
        })
    });
}

fn filter_checking(c: &mut Criterion) {
    c.bench_function("checking a filter list", |b| {
        let mut filter = blackhole::filter::Filter::default();
        let entries =
            blackhole::filter::rules::Rules::parse(Path::new("benches/test.txt")).unwrap();
        filter.rules.insert(entries);

        let request = Request::new(
            MessageRequest::read(&mut BinDecoder::new(&[
                0xf6, 0x3d, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x67,
                0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08,
                0xcf, 0xef, 0x93, 0x5b, 0x92, 0xad, 0x6e, 0xdf,
            ]))
            .unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );

        b.iter(|| black_box(filter.filter(&request)))
    });
}

criterion_group!(benches, filter_parsing, filter_checking);
criterion_main!(benches);
