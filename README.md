# datatoaster64

![Logo](logo.jpg) 

A small, perhaps optimistic, file system implementation written in Rust.

## Install

### Requirements

  * A modestly recent Ubuntu or Debian Linux system.
  * A recent rust nightly toolchain
  * FUSE development libraries:
```sh
sudo apt-get install fuse3 libfuse3-dev
```

### Procedure

```sh
cd $THIS_REPO

# Create an empty filesystem image in data.toast
cargo run --release format

# This commands stays in the foreground as long as the filesystem is mounted.
# You may access the directory with another terminal in the mean time.
# Press Ctrl-C when you are done.
cargo run --release mount mnt
```

## FAQ

### Why 64 bits ?

48 bit block indexes are awkward to deal with and does not sound like a game I would have liked to receive at Christmas.
