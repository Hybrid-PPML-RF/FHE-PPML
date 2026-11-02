# ============================================================================
# Related-work Docker image for private decision tree / random forest training
# Implements / wraps:
#   1. MP-SPDZ v0.4.x  — includes:
#        • Hamada et al. PoPETs 2023  (TreeTrainer in decision_tree.py)
#        • Abspoel et al. PoPETs 2021 (TreeClassifier in decision_tree.py)
#   2. Bhardwaj et al. CCS 2024       — PR #1449 on sandy9999/MP-SPDZ fork
#   3. philips-software/random_forest — MPyC RF (Abspoel et al. RF variant)
#   4. Akavia et al. TOPSEC 2022      — intuit/Decision-Trees-over-FHE (CKKS/SEAL)
#
# NOT available as code: Hashemi/Shin et al. ESORICS 2024
# ============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC LANG=C.UTF-8

# ── System dependencies ───────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        automake build-essential clang cmake git ca-certificates bzip2 \
        libgmp-dev libntl-dev libsodium-dev libssl-dev zlib1g-dev libbz2-dev \
        libtool m4 python3 python3-dev python3-pip \
        texinfo yasm curl wget \
        libdpkg-perl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir scikit-learn pandas numpy mpyc

# ── Boost >= 1.75 (Ubuntu 22.04 has 1.74; MP-SPDZ's libOTe needs 1.75, and the boost download of the cryptoTools
#    version pinned by the Bhardwaj et al. fork points to a mirror that no longer exists) ─────────────────────────
RUN set -eux; \
    curl -fsSL -o /tmp/boost.tar.bz2 https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.bz2; \
    echo "6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e  /tmp/boost.tar.bz2" | sha256sum -c -; \
    tar xjf /tmp/boost.tar.bz2 -C /tmp; cd /tmp/boost_1_83_0; \
    ./bootstrap.sh --prefix=/usr/local --with-libraries=system,thread,filesystem,iostreams,regex,chrono,atomic,date_time; \
    ./b2 -j"$(nproc)" -d0 link=shared,static threading=multi variant=release install; \
    cd /; rm -rf /tmp/boost*; ldconfig

# ── Build MP-SPDZ (main branch = Hamada + Abspoel) ───────────────────────
WORKDIR /opt/mp-spdz
RUN git clone --depth 1 --branch v0.4.1 https://github.com/data61/MP-SPDZ.git .

# Build the two protocol binaries most relevant to the paper's comparison:
#   replicated-ring-party.x  — 3-party honest-majority ring (≈ paper's model)
#   semi2k-party.x           — 2-party semi-honest (fast local benchmark)
#   mascot-party.x           — 2-party malicious (strongest security)
RUN make -j$(nproc) replicated-ring-party.x semi2k-party.x

# ── Build Bhardwaj et al. fork (PR #1449 = branch master of sandy9999/MP-SPDZ, pinned to its head commit) ──
# (the branch "PrivateDT" used before does not exist). If unreachable, skip (BHARDWAJ_AVAILABLE=0).
# The root Dockerfile of FHE-PPML builds the same fork for Figure 5 / Table 5 (scripts/build_bhardwaj.sh).
WORKDIR /opt/mp-spdz-bhardwaj
RUN git init -q . && git remote add origin https://github.com/sandy9999/MP-SPDZ.git \
    && git fetch -q --depth 1 origin 87d1e5c7850fff6b91de95efb6e62752b5891d7f && git checkout -q FETCH_HEAD \
    && make -j$(nproc) replicated-ring-party.x semi2k-party.x \
    && echo "BHARDWAJ_AVAILABLE=1" > /opt/bhardwaj_status \
    || (echo "BHARDWAJ_AVAILABLE=0" > /opt/bhardwaj_status \
        && echo "[WARN] Bhardwaj et al. fork unavailable; skipping")

# ── Clone philips-software/random_forest (MPyC, Abspoel RF) ──────────────
WORKDIR /opt/mpyc-rf
RUN git clone --depth 1 https://github.com/philips-software/random_forest.git .

# ── Build SEAL 4.0.0 (required by Akavia et al.) ─────────────────────────
RUN git clone --depth 1 --branch 4.0.0 \
        https://github.com/microsoft/SEAL.git /tmp/seal400 \
    && cmake -S /tmp/seal400 -B /tmp/seal400/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DSEAL_BUILD_TESTS=OFF \
        -DSEAL_BUILD_EXAMPLES=OFF \
    && cmake --build /tmp/seal400/build --parallel $(nproc) \
    && cmake --install /tmp/seal400/build \
    && rm -rf /tmp/seal400

# ── Build Akavia et al. Decision-Trees-over-FHE ───────────────────────────
RUN git clone --depth 1 \
        https://github.com/intuit/Decision-Trees-over-FHE.git \
        /opt/decision-trees-fhe
COPY akavia_main.cpp         /opt/decision-trees-fhe/src/main.cpp
COPY akavia_CMakeLists.txt   /opt/decision-trees-fhe/CMakeLists.txt
RUN cmake -S /opt/decision-trees-fhe -B /opt/decision-trees-fhe/build \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/decision-trees-fhe/build --parallel $(nproc) \
        --target fhe_random_forest

# ── Install our orchestration scripts ────────────────────────────────────
WORKDIR /opt/related-work
COPY mpc_programs/    mpc_programs/
COPY prepare_data.py  prepare_data.py
COPY run_mpyc_rf.py   run_mpyc_rf.py
COPY entrypoint.sh    entrypoint.sh
RUN chmod +x entrypoint.sh

# Pre-create MP-SPDZ directories expected at runtime
RUN mkdir -p /opt/mp-spdz/Player-Data \
             /opt/mp-spdz-bhardwaj/Player-Data

ENTRYPOINT ["/opt/related-work/entrypoint.sh"]
CMD ["--help"]
