use std::{convert::TryInto, path::Path};

use blackhole::dns::{
    header::Header,
    packet::{Buffer, Packet, ResizableBuffer},
    qualified_name::QualifiedName,
    question::Question,
    traits::FromBuffer,
    DNSError, QueryType, Record, ResultCode, Ttl, RR,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn packet() -> Packet {
    Packet {
        header: Header {
            id: 56029,
            recursion_desired: true,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: true,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: true,
            z: false,
            recursion_available: true,
            questions: 1,
            answers: 2,
            authoritative_entries: 0,
            resource_entries: 0,
        },
        questions: vec![Question {
            name: QualifiedName("example.com".into()),
            qtype: QueryType::MX,
        }],
        answers: vec![
            Record::MX {
                record: RR {
                    domain: QualifiedName("example.com".into()),
                    ttl: Ttl(3600),
                    query_type: QueryType::MX,
                    class: 1,
                    data_length: 20,
                },
                priority: 10,
                host: QualifiedName("mail.example.com".into()),
            },
            Record::MX {
                record: RR {
                    domain: QualifiedName("example.com".into()),
                    ttl: Ttl(3600),
                    query_type: QueryType::MX,
                    class: 1,
                    data_length: 23,
                },
                priority: 20,
                host: QualifiedName("mailsec.example.com".into()),
            },
        ],
        authorities: vec![],
        resources: vec![],
    }
}

fn create_buffer<T>() -> T
where
    Packet: TryInto<T, Error = DNSError>,
{
    packet().try_into().unwrap()
}

pub fn packet_to_buffer(c: &mut Criterion) {
    c.bench_function("creating a buffer", |b| {
        let packet = packet();

        b.iter(|| black_box(Buffer::try_from(packet.clone()).unwrap()))
    });
}

pub fn buffer_to_packet(c: &mut Criterion) {
    c.bench_function("creating a packet", |b| {
        let mut buffer = create_buffer::<Buffer>();

        b.iter(|| black_box(Packet::from_buffer(&mut buffer).unwrap()))
    });
}

pub fn packet_to_resizeable_buffer(c: &mut Criterion) {
    c.bench_function("creating a resizeable buffer", |b| {
        let packet = packet();

        b.iter(|| black_box(ResizableBuffer::try_from(packet.clone()).unwrap()))
    });
}

pub fn resizeable_buffer_to_packet(c: &mut Criterion) {
    c.bench_function("creating a packet from a resizeable buffer", |b| {
        let mut buffer = create_buffer::<ResizableBuffer>();

        b.iter(|| black_box(Packet::from_buffer(&mut buffer).unwrap()))
    });
}

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

        let packet = packet();

        b.iter(|| black_box(filter.filter(&packet)))
    });
}

criterion_group!(
    benches,
    packet_to_buffer,
    buffer_to_packet,
    packet_to_resizeable_buffer,
    resizeable_buffer_to_packet,
    filter_parsing,
    filter_checking
);
criterion_main!(benches);
