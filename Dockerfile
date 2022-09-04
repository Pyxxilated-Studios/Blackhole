FROM rust as build

WORKDIR /blackhole

COPY . .

RUN rm ./target/release/*blackhole*
RUN cargo build --release

FROM debian:buster-slim

# Copy build artifact from build stage
COPY --from=build /blackhole/target/release/blackhole .

VOLUME /config

ENV LOG_LEVEL="error"

EXPOSE 6379/udp

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "dig", "-p", "6379", "example.com" ]

ENTRYPOINT ["./blackhole"]
