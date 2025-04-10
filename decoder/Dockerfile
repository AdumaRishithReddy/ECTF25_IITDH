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
RUN apt install -y libnewlib-arm-none-eabi build-essential libc6-dev



# Install python and pip and pycryptodome
RUN apt-get install -y python3-pip && pip3 install pycryptodome --break-system-packages

RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip





ENV MAXIM_PATH=/root/msdk-2024_02



WORKDIR /decoder

RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.6-stable.zip && \
    unzip v5.7.6-stable.zip && \
    mv wolfssl-5.7.6-stable wolfssl && \
    rm v5.7.6-stable.zip

WORKDIR /decoder/wolfssl

# ENV CC=arm-none-eabi-gcc \
#     AR=arm-none-eabi-ar \
#     LD=arm-none-eabi-ld \
#     RANLIB=arm-none-eabi-ranlib

RUN ./autogen.sh && \
    ./configure   \
    --host=arm-none-eabi \
    CC=arm-none-eabi-gcc \
    LD=arm-none-eabi-ld \
    AR=arm-none-eabi-ar \
    STRIP=arm-none-eabi-strip \
    RANLIB=arm-none-eabi-ranlib \
    --enable-ecc \
    --enable-pwdbased \
    --enable-ed25519 \
    --disable-shared \
    --enable-static \
    --enable-sp-math \
    --enable-sp \
    --disable-crypttests \
    --disable-filesystem \
    --prefix=/usr/local/arm-none-eabi \  
    CFLAGS="\
    --specs=rdimon.specs -mcpu=cortex-m4 -mthumb  \
    -mfloat-abi=soft -mfpu=fpv4-sp-d16 -Os \
    -DNO_WOLFSSL_DIR -DHAVE_PK_CALLBACKS -DWOLFSSL_USER_IO -DNO_WRITEV \
    # -mcpu=cortex-m4 -mthumb -Os \
    -DWOLFSSL_PUBLIC_MP \
    -DUSE_INTEGER_HEAP_MATH \
    -UHAVE___UINT128_T \
    -DWOLFSSL_SP_NO_MALLOC \
    -DWOLFSSL_SP_NO_DYN_STACK \
    -DHAVE_ED25519 \
    -DHAVE_ED25519_VERIFY \
    -DHAVE_ED25519_KEY_IMPORT" && \
    make clean 
    
RUN make

RUN make install


WORKDIR /decoder

ENTRYPOINT ["bash", "-c","cp /decoder/src/decoder_core_func.c /out/decoder_core_func.c.bak && \
    python3 /decoder/build_scripts/replace_keys.py /decoder/src/decoder_core_func.c /global.secrets 0xDEADBEEF && \
    make release DECODER_ID=${DECODER_ID}; \
    cp build/max78000.elf build/max78000.bin /out; \
    cp /out/decoder_core_func.c.bak /decoder/src/decoder_core_func.c"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder