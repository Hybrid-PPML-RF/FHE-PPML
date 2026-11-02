# =====================================================================================================================
# Artifact image of "Secure Private Random Forest Training via FHE and MPC" (hybrid FHE + MPC random forest training).
#
#   docker build -t fhe-ppml --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) .
#   docker run --rm -v "$PWD/results:/results" fhe-ppml --quick       # smoke test (minutes)
#   docker run --rm -v "$PWD/results:/results" fhe-ppml               # Table 4, Table 5, Figure 5 (see README)
#   docker run --rm fhe-ppml --help                                   # options; other entry points: README
#
# Contents (/opt/FHE-PPML = this repository):
#   build/ppml, build/test_*        FHE benchmark (main_integrity.cpp) and tests, Microsoft SEAL 4.1
#   mpc/sy-shamir-party.x           our MP-SPDZ fork (Shamir with MAC, prime field up to 320 bits: CONFIG.mine)
#   /opt/baselines/mp-spdz-bhardwaj MP-SPDZ fork of Bhardwaj et al. (CCS'24, MP-SPDZ PR #1449)  [WITH_BASELINES=1]
#   scripts/                        reproduction scripts (entry point: scripts/docker-entrypoint.sh)
#
# Build arguments:
#   WITH_HEXL=ON|OFF       SEAL with Intel HEXL (AVX-512 acceleration, runtime CPU detection); default ON as in the
#                          original build instructions on c6i.32xlarge
#   MARCH=native|...       -march for MP-SPDZ (default native: build the image on the machine type you run it on)
#   WITH_BASELINES=1|0     build the Bhardwaj et al. baseline (default 1; ~10 min)
#   GIT_COMMIT=<hash>      recorded in results/run_info.txt
# All downloaded sources are pinned to a tag or commit.
# =====================================================================================================================
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates curl bzip2 pkg-config \
        clang automake autoconf libtool m4 yasm \
        libgmp-dev libntl-dev libsodium-dev libssl-dev openssl zlib1g-dev libbz2-dev \
        python3 python3-matplotlib \
        iproute2 iputils-ping procps psmisc util-linux time openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ---- Boost >= 1.75 ---------------------------------------------------------------------------------------------------
# Ubuntu 22.04 ships 1.74; libOTe/cryptoTools (MP-SPDZ dependency) need 1.75, and the fallback download of the pinned
# cryptoTools in the Bhardwaj et al. fork points to a mirror that no longer exists. Same version as Ubuntu 24.04.
ARG BOOST_VERSION=1.83.0
ARG BOOST_SHA256=6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e
RUN set -eux; v=$(echo "$BOOST_VERSION" | tr . _); \
    curl -fsSL -o /tmp/boost.tar.bz2 "https://archives.boost.io/release/${BOOST_VERSION}/source/boost_${v}.tar.bz2"; \
    echo "${BOOST_SHA256}  /tmp/boost.tar.bz2" | sha256sum -c -; \
    tar xjf /tmp/boost.tar.bz2 -C /tmp; cd "/tmp/boost_${v}"; \
    ./bootstrap.sh --prefix=/usr/local --with-libraries=system,thread,filesystem,iostreams,regex,chrono,atomic,date_time; \
    ./b2 -j"$(nproc)" -d0 link=shared,static threading=multi variant=release install; \
    cd /; rm -rf /tmp/boost*; ldconfig

# ---- Microsoft SEAL 4.1 -----------------------------------------------------------------------------------------------
ARG SEAL_VERSION=v4.1.2
ARG WITH_HEXL=ON
RUN set -eux; \
    git clone --depth 1 --branch "$SEAL_VERSION" https://github.com/microsoft/SEAL.git /tmp/SEAL; \
    cmake -S /tmp/SEAL -B /tmp/SEAL/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DSEAL_USE_INTEL_HEXL="$WITH_HEXL" -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF -DSEAL_BUILD_BENCH=OFF; \
    cmake --build /tmp/SEAL/build -j"$(nproc)"; \
    cmake --install /tmp/SEAL/build; \
    rm -rf /tmp/SEAL

# ---- our MP-SPDZ fork (mpc/, based on MP-SPDZ 0.4.1): sy-shamir-party.x ------------------------------------------------
# scripts/build_mpspdz.sh fetches MP-SPDZ's dependencies at the commits pinned by MP-SPDZ v0.4.1 (mpc/ is not a git
# submodule, so MP-SPDZ's own "git submodule update" cannot be used) and builds with mpc/CONFIG.mine (prime <= 320 bits).
ARG MARCH=native
WORKDIR /opt/FHE-PPML
COPY mpc/ mpc/
COPY scripts/build_mpspdz.sh scripts/build_bhardwaj.sh scripts/
RUN set -eux; scripts/build_mpspdz.sh --march "$MARCH" sy-shamir-party.x; find mpc -name '*.o' -delete

# ---- baseline: Bhardwaj et al., CCS'24 = head of https://github.com/data61/MP-SPDZ/pull/1449 (sandy9999/MP-SPDZ) ---------
ARG WITH_BASELINES=1
RUN set -eux; \
    if [ "$WITH_BASELINES" = 1 ]; then \
      scripts/build_bhardwaj.sh --dir /opt/baselines/mp-spdz-bhardwaj --march "$MARCH" ps-rep-ring-party.x replicated-ring-party.x; \
      find /opt/baselines/mp-spdz-bhardwaj -name '*.o' -delete; \
    fi

# ---- FHE benchmark (ppml) ----------------------------------------------------------------------------------------------
COPY CMakeLists.txt *.cpp *.h ./
RUN set -eux; \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; \
    cmake --build build -j"$(nproc)" --target ppml test_share; \
    cmake --build build -j"$(nproc)" -- -k || echo "WARNING: some optional test binaries did not build"; \
    ls -l build/ppml build/test_*

# ---- scripts, certificates, compiled MPC programs ---------------------------------------------------------------------
ARG GIT_COMMIT=unknown
ENV RESULTS_DIR=/results \
    PPML_BIN=/opt/FHE-PPML/build/ppml \
    MPSPDZ_DIR=/opt/FHE-PPML/mpc \
    BHARDWAJ_DIR=/opt/baselines/mp-spdz-bhardwaj \
    GIT_COMMIT=${GIT_COMMIT}
COPY scripts/ scripts/
COPY README.md ./
# - one set of SSL certificates for the 10 MPC parties (and the 3 baseline parties), valid 10 years: every container of
#   this image has the same files, which is what a run on several machines needs (same image on all machines, README)
# - compile all MP-SPDZ programs of the evaluation (seconds; the build fails if one does not compile)
# - unit tests of the log parsers / table and figure generation
RUN set -eux; chmod +x scripts/*.sh; \
    scripts/setup_ssl.sh 10 mpc/Player-Data; \
    if [ -d "$BHARDWAJ_DIR" ]; then scripts/setup_ssl.sh 3 "$BHARDWAJ_DIR/Player-Data"; fi; \
    scripts/run_mpc.sh --program ours --compile-only; \
    scripts/run_mpc.sh --program mpconly --compile-only; \
    python3 scripts/tests/test_make_results.py

VOLUME /results
ENTRYPOINT ["/opt/FHE-PPML/scripts/docker-entrypoint.sh"]
CMD []
