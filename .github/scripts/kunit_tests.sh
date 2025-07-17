#!/bin/bash
# SPDX-FileCopyrightText: 2025 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -euox pipefail
d=$(dirname "${BASH_SOURCE[0]}")
. $d/series/utils.sh

logs=$(get_logs_dir)
f=${logs}/kunit-tests.log

KERNEL_PATH=$(find "$1" -name '*vmlinu[zx]*')

ROOTFS_PATH=$(find /rootfs/ -name 'rootfs_rv64_ubuntu*.ext4')
# Resize the fs
truncate -s +4G $ROOTFS_PATH
resize2fs $ROOTFS_PATH

virt-copy-in -a $ROOTFS_PATH $1/lib/modules /lib/

build_name=$(cat "$1/kernel_version")

# The Docker image comes with a prebuilt python environment with all tuxrun
# dependencies
source /build/.env/bin/activate

mkdir -p /build/squad_json/

/build/tuxrun/run --runtime null --device qemu-riscv64 --kernel $KERNEL_PATH --tests kunit --results /build/squad_json/kunit.json --log-file-text /build/squad_json/kunit.log --timeouts kunit=480 --rootfs $ROOTFS_PATH --boot-args "rw" || true

# Convert JSON to squad datamodel
python3 /build/my-linux/.github/scripts/series/tuxrun_to_squad_json.py --result-path /build/squad_json/kunit.json --testsuite kunit
python3 /build/my-linux/.github/scripts/series/generate_metadata.py --logs-path /build/squad_json/ --job-url ${GITHUB_JOB_URL} --branch ${GITHUB_BRANCH_NAME}

curl --header "Authorization: token $SQUAD_TOKEN" --form tests=@/build/squad_json/kunit.squad.json --form log=@/build/squad_json/kunit.log --form metadata=@/build/squad_json/metadata.json https://squad.di.riseproject.dev/api/submit/riscv-linux/linux-all/${build_name}/qemu
