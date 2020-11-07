FROM debian:buster-20201012-slim
# FROM alpine:3.12.1

RUN apt update && \
    apt install -y openssl ca-certificates && \
    apt clean
# RUN apk add --no-cache openssl

WORKDIR /app
COPY target/release/cert-sync ./cert-sync

CMD ["./cert-sync"]
