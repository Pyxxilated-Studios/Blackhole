FROM rust as build

RUN USER=root cargo new --bin blackhole
WORKDIR /blackhole

RUN mv ./src ./bin
RUN mkdir lib && touch lib/src.rs

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Cache Dependencies
RUN cargo build --release
RUN rm bin/*.rs lib/*.rs

COPY ./bin ./bin
COPY ./lib ./lib

RUN rm ./target/release/deps/*blackhole*
RUN cargo build --release

FROM debian:buster-slim

# Copy build artifact from build stage
COPY --from=build /blackhole/target/release/blackhole .

VOLUME /config

ENV LOG_LEVEL="error"

EXPOSE 6379

ENTRYPOINT ["./blackhole"]
