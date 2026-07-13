FROM rust:1.97 as builder

WORKDIR /tmp

ADD src/ src/

ADD Cargo.lock Cargo.toml /tmp/

RUN ls /tmp && cargo build --release

FROM debian

LABEL org.opencontainers.image.title="k8s-ldap-auth-rs" \
      org.opencontainers.image.description="A webhook authentication server for a Kubernetes cluster" \
      org.opencontainers.image.authors="Thiago Castro" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /tmp/target/release/k8s-ldap-auth-rs /bin/

VOLUME /etc/k8s-ldap-auth-rs/

USER www-data

ENTRYPOINT ["k8s-ldap-auth-rs"]
