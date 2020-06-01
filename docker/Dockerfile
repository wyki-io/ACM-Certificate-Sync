FROM rust:1.43.1-slim-buster

WORKDIR /app
COPY ./target/debug/acs ./

EXPOSE 3030

CMD ["./acs"]
