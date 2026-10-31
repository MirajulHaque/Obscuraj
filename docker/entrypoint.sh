#!/bin/sh
# Author: Md Mirajul Haque Miraj
# Copyright 2026 Md Mirajul Haque Miraj
# SPDX-License-Identifier: Apache-2.0
# Role: Cybersecurity Consultant
# Project: ObscuraJ

set -eu

mkdir -p /app/data/raw /app/data/reports
chown -R obscuraj:obscuraj /app/data
exec gosu obscuraj "$@"
