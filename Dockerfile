FROM node:20-bullseye-slim as client

WORKDIR /client

# Generate cached dependencies
COPY ./client/package.json ./client/yarn.lock ./
RUN yarn install --network-timeout 600000

COPY ./client .
RUN yarn build

FROM rust:1-alpine as chef
WORKDIR /blackhole

RUN apk add musl-dev pkgconfig git clang mold
RUN rustup set profile minimal
RUN rustup default nightly

ENV RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=/usr/bin/mold"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_UNSTABLE_SPARSE_REGISTRY=true
ENV CARGO_INCREMENTAL=0

RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as server
COPY --from=planner /blackhole/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release

FROM oven/bun

RUN apt update && apt install -y dnsutils ca-certificates

WORKDIR /blackhole

COPY --from=client /client/build .
COPY ./client/package.json .
COPY --from=server /blackhole/target/release/blackhole .
COPY ./entrypoint.bash .

VOLUME /config

EXPOSE 53/tcp 53/udp 3000 5000

ENV LOG_LEVEL="info"

# See https://github.com/gornostay25/svelte-adapter-bun/issues/39
ENV PROTOCOL_HEADER=x-forwarded-proto
ENV HOST_HEADER=x-forwarded-host

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "dig", "-p", "53", "example.com", "@127.0.0.1" ]

ENTRYPOINT [ "./entrypoint.bash" ]

CMD [ "start" ]
