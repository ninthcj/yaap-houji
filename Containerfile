FROM docker.io/library/ubuntu@sha256:9a04f13b3f80ef056361e30868593b1cfd2279fe19e4081cb93a90bf56819d6a

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        apksigner bc bison build-essential ca-certificates ccache cpio curl \
        file flex g++-multilib gcc-multilib git git-lfs gperf jq lib32ncurses-dev \
        lib32readline-dev lib32z1-dev libelf-dev libgl1-mesa-dev libncurses6 \
        libssl-dev libxml2-utils lz4 openjdk-21-jdk-headless openssl patchelf \
        pngcrush python3 repo rsync unzip wget xz-utils zip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
WORKDIR /workspace
