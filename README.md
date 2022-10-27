# omnect-eisutils
Implementation of eis_utils in pure Rust.

This crate relies heavily on the functionality already provided by [the iot-identity-services](https://github.com/Azure/iot-identity-service).

# Running the tests
Please create a directory /run/aziot and give the user running this test rwx permissions to this directory:

```
sudo mkdir -p /run/aziot && sudo chown `whoami` /run/aziot
```

Also since the tests need to switch services in between test cases, run the tests sequentially:

```
cargo test -- --test-threads=1
```
