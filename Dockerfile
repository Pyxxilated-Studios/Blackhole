FROM node:18-buster-slim as client

WORKDIR /client

# Generate cached dependencies
COPY ./client/package.json ./client/yarn.lock ./
RUN yarn install

COPY ./client .
RUN yarn build

FROM rustlang/rust:nightly as server

RUN USER=root cargo new --bin blackhole
WORKDIR /blackhole

# Generate cached dependencies
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN mkdir lib
RUN touch lib/src.rs
RUN cargo build --release

# Now build the actual server
RUN rm src/*.rs lib/*.rs
RUN find target/release -maxdepth 1 -type f -delete
COPY ./src ./src
COPY ./lib ./lib
RUN touch src/main.rs lib/src.rs
RUN cargo build --release

FROM node:18-buster-slim

WORKDIR /blackhole

COPY --from=client /blackhole/target/release/blackhole .
COPY --from=server /client/build .
COPY ./client/package.json .

COPY ./entrypoint.sh .

VOLUME /config

ENV LOG_LEVEL="warn"

EXPOSE 6379/tcp 6379/udp 3000 5000

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "dig", "-p", "6379", "example.com", "@127.0.0.1" ]

ENTRYPOINT ["bash", "entrypoint.sh"]
