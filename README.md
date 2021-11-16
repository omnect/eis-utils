# ics-dm-eisutils-rs
Implementation of eis_utils in pure Rust

This create relies heavily on the functionality already provided by the iot-identity-services which it includes
as a git submodule. Initialize this submodule using:

```
git submodule init
```

# Running the tests
Please create a directory /run/aziot and give the user running this test rwx permissions to this directory:

```
sudo mkdir -p /run/aziot && isudo chown `whoami` /run/aziot
```

Also since the tests need to switch services in between test cases, run the tests sequentially:

```
cargo test -- --test-threads=1
```
