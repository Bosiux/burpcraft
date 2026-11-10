# burpcraft-server (self-hosted Collaborator + BApp Store) only; the desktop app is not containerised.
#   docker build -t burpcraft-server .
#   docker run -p 8053:8053 burpcraft-server                                  # local, path-based payloads
#   docker run -p 53:5353/udp -p 80:8080 -p 25:2525 burpcraft-server \
#     --domain oast.example.com --public-ip 203.0.113.7 --dns 5353 --http 8080 --smtp 2525 --secret s3cret
FROM rust:1.95-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p burpcraft-server

# no shell, no package manager, runs as an unprivileged user (hence the unprivileged ports above)
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/burpcraft-server /burpcraft-server
EXPOSE 8053
ENTRYPOINT ["/burpcraft-server", "--bind", "0.0.0.0"]
CMD ["--http", "8053"]
