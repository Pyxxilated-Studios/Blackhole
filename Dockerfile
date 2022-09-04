FROM node:18-buster-slim as clientbuild

WORKDIR /client

# Generate cached dependencies
COPY ./client/package.json ./client/yarn.lock ./
RUN yarn install

COPY ./client .
RUN yarn build

FROM rustlang/rust:nightly-slim as serverbuild

RUN USER=root cargo new --bin blackhole
WORKDIR /blackhole

# Generate cached dependencies
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN mkdir bin lib
RUN touch lib/src.rs
RUN mv src/main.rs bin/main.rs
RUN rmdir src
RUN cargo build --release

# Now build the actual server
RUN rm bin/*.rs lib/*.rs
COPY ./bin ./bin
COPY ./lib ./lib
RUN find target/release -maxdepth 1 -type f -delete
RUN cargo build --release

FROM node:18-buster-slim

WORKDIR /blackhole

COPY --from=serverbuild /blackhole/target/release/blackhole .
COPY --from=clientbuild /client/build .
COPY ./client/package.json .

COPY ./entrypoint.sh .

VOLUME /config

ENV LOG_LEVEL="error"

EXPOSE 6379/tcp 6379/udp 3000/tcp

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "dig", "-p", "6379", "example.com" ]

ENTRYPOINT ["bash", "entrypoint.sh"]
