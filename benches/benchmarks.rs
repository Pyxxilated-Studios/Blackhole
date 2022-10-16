use blackhole::dns::{
    header::Header,
    packet::{Buffer, Packet},
    qualified_name::QualifiedName,
    question::Question,
    traits::FromBuffer,
    QueryType, Record, ResultCode,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn packet_to_buffer(c: &mut Criterion) {
    c.bench_function("creating a buffer", |b| {
        let packet = Packet {
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
                name: QualifiedName("example.com".to_owned()),
                qtype: QueryType::MX,
            }],
            answers: vec![
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 10,
                    host: QualifiedName("mail.example.com".to_owned()),
                    ttl: 3600.into(),
                },
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".to_owned()),
                    ttl: 3600.into(),
                },
            ],
            authorities: vec![],
            resources: vec![],
        };

        b.iter(|| black_box(Buffer::try_from(packet.clone()).unwrap()))
    });
}

pub fn buffer_to_packet(c: &mut Criterion) {
    c.bench_function("creating a packet", |b| {
        let mut buffer: Buffer = Packet {
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
                name: QualifiedName("example.com".to_owned()),
                qtype: QueryType::MX,
            }],
            answers: vec![
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 10,
                    host: QualifiedName("mail.example.com".to_owned()),
                    ttl: 3600.into(),
                },
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".to_owned()),
                    ttl: 3600.into(),
                },
            ],
            authorities: vec![],
            resources: vec![],
        }
        .try_into()
        .unwrap();

        b.iter(|| black_box(Packet::from_buffer(&mut buffer).unwrap()))
    });
}

criterion_group!(benches, packet_to_buffer, buffer_to_packet);
criterion_main!(benches);
