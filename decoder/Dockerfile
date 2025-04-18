# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.10

LABEL version="0.2"
LABEL description="IITDH eCTF 2025 Docker Instance"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
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
RUN apt install -y libc6-dev

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

WORKDIR /wolfssl

RUN bash ./autogen.sh

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "\
    cd /decoder && \
    cp -r /wolfssl . && \
    cp /decoder/src/decoder_core_func.c /out/decoder_core_func.c.bak && \
    python3 /decoder/build_scripts/replace_keys.py /decoder/src/decoder_core_func.c /global.secrets ${DECODER_ID} && \
    make release DECODER_ID=${DECODER_ID}; \
    cp /out/decoder_core_func.c.bak /decoder/src/decoder_core_func.c; \
    rm -r wolfssl; \
    cp build/max78000.elf build/max78000.bin /out;"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
