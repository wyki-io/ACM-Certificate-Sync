FROM rust:1.43.1-slim-buster as builder

RUN USER=root cargo new --bin app
WORKDIR /app

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN ls -la
RUN cargo build --release

COPY ./src ./src

# RUN rm ./target/release/deps/cert_manager_acm_sync*
RUN cargo build --release

FROM rust:1.43.1-slim-buster

WORKDIR /app
COPY --from=builder /app/target/release/cert-manager-acm-sync ./

EXPOSE 3030

CMD ["./cert-manager-acm-sync"]