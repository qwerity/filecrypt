FROM gentoo/stage3:latest

ENV FEATURES="-usersandbox"

SHELL ["/bin/bash", "-c"]

# 1) Seed & sync Portage, then update Portage itself (Gentoo recommends this)
RUN emerge-webrsync && \
    emerge --oneshot --quiet-build=y sys-apps/portage && \
    emaint sync -r gentoo

# 2) Install toolchain: cmake, ninja, gcc, OpenSSL, pkg-config
#    NOTE: cmake & ninja are in dev-build/* (not dev-util/*)
RUN emerge -n --quiet-build=y \
      dev-build/cmake \
      dev-build/ninja \
      sys-devel/gcc \
      dev-libs/openssl \
      dev-util/pkgconf && \
    rm -rf /var/cache/distfiles/* /var/cache/binpkgs/*

WORKDIR /workspace

COPY . /workspace

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && \
    cmake --build build -j8 && \
    (cd build && ctest --verbose && cp filecrypt /usr/local/bin/filecrypt && cp -r ../build /tmp/build-cache)

RUN keyHex=$(openssl rand -hex 32) && \
    openssl ecparam -name prime256v1 -genkey -noout -out private.pem && \
    openssl ec -in private.pem -pubout -out public.pem && \
    printf 'Gentoo test message\n' > sample.txt && \
    signatureHex=$( \
        ./build/filecrypt encrypt --in sample.txt --out cipher.bin --enc-key "$keyHex" \
                                  --sign-key private.pem | awk '/Signature \(hex\): / {print $3}' \
    ) && \
    test -n "$signatureHex" && \
    ./build/filecrypt decrypt --in cipher.bin --out restored.txt --enc-key "$keyHex" \
                              --verify-key public.pem --signature "$signatureHex" && \
    cmp sample.txt restored.txt

ENTRYPOINT ["/usr/local/bin/filecrypt"]
