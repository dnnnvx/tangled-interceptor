FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/tangled-interceptor /interceptor
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/interceptor"]
