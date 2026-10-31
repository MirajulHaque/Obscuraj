# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

# ----------------------------------------
# Base Image
# ----------------------------------------
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

# ----------------------------------------
# Set Working Directory
# ----------------------------------------
WORKDIR /app

# ----------------------------------------
# Install System Dependencies
# ----------------------------------------
RUN sed -i \
    -e 's|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/20261027T000000Z|' \
    -e 's|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/20261027T000000Z|' \
    /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y \
    bash=5.2.37-2+b10 \
    bind9-dnsutils=1:9.20.30-1~deb13u1 \
    ca-certificates=20250419+deb13u1 \
    coreutils=9.7-3 \
    curl=8.14.1-2+deb13u7 \
    gosu=1.17-3+b4 \
    jq=1.7.1-6+deb13u4 \
    mawk=1.3.4.20250131-1 \
    --no-install-recommends \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 obscuraj \
    && useradd --uid 10001 --gid 10001 --home-dir /home/obscuraj \
       --create-home --shell /usr/sbin/nologin obscuraj

# ----------------------------------------
# Copy Project Files
# ----------------------------------------
COPY . /app

# ----------------------------------------
# Install Python Dependencies
# ----------------------------------------
RUN pip install --no-cache-dir -r requirements-lock.txt

# ----------------------------------------
# Create Required Directories
# ----------------------------------------
RUN mkdir -p /app/data/raw /app/data/reports \
    && chown -R obscuraj:obscuraj /app/data

COPY docker/entrypoint.sh /usr/local/bin/obscuraj-entrypoint
COPY docker/check-runtime.sh /usr/local/bin/obscuraj-runtime-check
RUN chmod 0755 /usr/local/bin/obscuraj-entrypoint /usr/local/bin/obscuraj-runtime-check \
    && gosu obscuraj /usr/local/bin/obscuraj-runtime-check

# ----------------------------------------
# Expose Port
# ----------------------------------------
EXPOSE 19191

# ----------------------------------------
# Run Application
# ----------------------------------------
ENV OBSCURAJ_HOST=0.0.0.0
ENTRYPOINT ["/usr/local/bin/obscuraj-entrypoint"]
CMD ["python", "-m", "api.main"]
