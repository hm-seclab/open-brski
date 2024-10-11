# Signeable Payload

`SigneablePayload` is a Rust crate designed to facilitate the creation, manipulation, and signing of payloads in various formats. It aims to provide a simple yet flexible interface for developers working on applications that require secure and verifiable data transactions.

## Features

- **JWS**: Supports JWS via josekit and Openssl
- **COSE**: Supports COSE signatures via coset and ring

## Getting Started

To use `SigneablePayload`, add it as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
signeable_payload = "0.1.0"