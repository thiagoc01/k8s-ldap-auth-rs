FROM rust:1.96.1 as builder

WORKDIR /tmp

ADD src/ src/

ADD Cargo.lock Cargo.toml /tmp/

RUN ls /tmp && cargo build --release

FROM debian

COPY --from=builder /tmp/target/release/k8s-ldap-auth-rs /bin/

ENTRYPOINT ["k8s-ldap-auth-rs"]
