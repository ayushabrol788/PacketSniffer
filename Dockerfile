FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libpcap-dev \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc)

WORKDIR /app/build

CMD ["./packet_sniffer"]
