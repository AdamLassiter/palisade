#!/usr/bin/env bash

./cargow build --release
./cargow test --release

dd if=/dev/urandom of=/tmp/evfs-test-master.key bs=32 count=1

cd lazytest
EVFS_KEYFILE=/tmp/evfs-test-master.key \
  LD_PRELOAD="../sqlshim/target/release/libsqlshim.so" \
  RUST_BACKTRACE=full \
  ./target/release/lazytest
