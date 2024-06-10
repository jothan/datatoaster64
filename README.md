# datatoaster64

![Logo](logo.jpg) 

A small, perhaps optimistic, file system implementation written in Rust.

## Install

### Requirements

  * A modestly recent Ubuntu or Debian Linux system.
  * A recent rust nightly toolchain
  * FUSE and libnotify development libraries:
```sh
sudo apt-get install fuse3 libfuse3-dev libnotify-dev
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

### Design

This small file system takes inspiration from the early UFS and EXT2 file systems, implementing operations that are centered around inodes.

### Supported operations

 * file creation, open, read, write, close, rename, link, unlink
 * mkdir, opendir, readdir, rmdir

### Features

 * ___#[no_std]___ support for the file system implementation.
 * A file system implementation with fine-grained locking and concurrency taken into account.
 * No checksumming, journal or data left after a crash.

### Code structure

The file system is implemented in 4 separate crates

datatoaster64
: This crate contains a CLI tool for formatting and mounting filesystems using FUSE. It is responsible for parsing command line arguments, logging initialization and implementing a fake block device over a regular file.

datatoaster-core
: The abstract file system implementation. It accepts file operation requests via function calls. It can be used in a ___#[no_std]___ environment (with a memory allocator).

datatoaster-fuse
: This is a sample usage of datatoaster-core, making it work with the FUSE protocol that allows a user-space application to provide a file system interface.

datatoaster-traits
: This exports the trait for accessing a block device.


### Locking design

Operations on distinct inodes are independent of each other. The main interaction is via the block allocator that can presently only serve one request at a time. Care has been taken to take locks in a consistent manner across the whole file system.

File handle locking life cycle :
 * The "file open counter" lock is acquired and released to mark the inode as open.
 * The global inode table lock is acquired and released to grab a reference to the inode handle.
 * The application performs operations on the inode, using the local inode lock to serialize operations.
 * On file closure:
  * The "file open counter" lock is acquired to decrement it while grabbing the specific's inode lock. The file open counter lock is then released.
  * If the file has an "open count" and a link count of zero, the inode is destroyed and the data blocks are released back to the allocator.

  Operations involving a directory and an object in that directory :
   * The inode locks are always acquired on the parent first, going in a parent to child direction.

  Operations involving two unrelated directories (rename) :
   * The operation waits to acquire the lock on the first directory and does a non-blocking locking attempt on the second directory. In the case of failure, the operation is retried by waiting for a lock on the second directory and doing a non-blocking locking attempt on the first directory. After a few tries, the operation fails with a deadlock error code.



## FAQ

### Why 64 bits ?

48 bit block indexes are awkward to deal with and does not sound like a game I would have liked to receive at Christmas.
