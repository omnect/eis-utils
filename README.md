# omnect-eisutils
Product page: https://www.omnect.io/home

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

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

---

copyright (c) 2021 conplement AG<br>
Content published under the Apache License Version 2.0 or MIT license, are marked as such. They may be used in accordance with the stated license conditions.
