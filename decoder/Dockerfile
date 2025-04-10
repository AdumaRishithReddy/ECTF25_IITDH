# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    git \
    wget \
    libtool \
    texinfo \
    unzip

# Install MSDK
RUN apt install -y libnewlib-arm-none-eabi libc6-dev build-essential

# Install python and pip and pycryptodome
RUN apt-get install -y python3-pip && pip3 install pycryptodome --break-system-packages

RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

WORKDIR /

RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip && \
    unzip v5.7.6-stable.zip && \
    mv wolfssl-5.7.6-stable wolfssl && \
    rm v5.7.6-stable.zip

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "\
    cd /decoder && \
    cp /decoder/src/decoder_core_func.c /out/decoder_core_func.c.bak && \
    python3 /decoder/build_scripts/replace_keys.py /decoder/src/decoder_core_func.c /global.secrets 0xDEADBEEF && \
    make release DECODER_ID=${DECODER_ID}; \
    cp /out/decoder_core_func.c.bak /decoder/src/decoder_core_func.c; \
    cp build/max78000.elf build/max78000.bin /out;"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
