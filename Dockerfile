FROM node:19-buster-slim as client

WORKDIR /client

# Generate cached dependencies
COPY ./client/package.json ./client/yarn.lock ./
RUN yarn install --network-timeout 600000

COPY ./client .
RUN yarn build

FROM rust:1.64-slim as server

RUN apt update && apt install -y pkg-config git
RUN rustup set profile minimal
RUN rustup default nightly

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN USER=root cargo new --bin blackhole
WORKDIR /blackhole

# Generate cached dependencies
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN mkdir lib
RUN mkdir benches
RUN touch benches/benchmarks.rs
RUN touch lib/src.rs
RUN cargo build --release

# Now build the actual server
RUN rm src/*.rs lib/*.rs
RUN find target/release -maxdepth 1 -type f -delete
COPY ./src ./src
COPY ./lib ./lib
RUN touch src/main.rs lib/src.rs
RUN cargo build --release

FROM denoland/deno:debian-1.27.0

RUN apt update && apt install -y dnsutils ca-certificates

WORKDIR /blackhole

COPY --from=client /client/build .
COPY ./client/package.json .
COPY --from=server /blackhole/target/release/blackhole .

COPY ./entrypoint.bash .

VOLUME /config

ENV LOG_LEVEL="info"

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "dig", "-p", "53", "example.com", "@127.0.0.1" ]

ENTRYPOINT [ "./entrypoint.bash" ]

CMD [ "start" ]
