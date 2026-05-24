FROM rust:bookworm

# Install the required iproute2 package
RUN apt update
RUN apt install -y iproute2

# Continue with your app setup
WORKDIR /app

RUN cargo
