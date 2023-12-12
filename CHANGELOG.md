# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] Q3 2023
- updated dependency iot-identity-service to 1.4.7
- removed user handle from dependency links

## [0.3.1] Q3 2023
- removed cargo ignore for RUSTSEC-2020-0071

## [0.3.0] Q3 2023
- made 'request_connection_string_from_eis_with_expiry' async
- removed main.rs and re-organized integration tests

## [0.2.6] Q1 2023
- fixed cargo clippy warnings
- prepared for open source

## [0.2.5] Q4 2022
- ignored RUSTSEC-2020-0071 introduced in 0.2.4

## [0.2.4] Q4 2022
- updated to iot-identity-service 1.4.1

## [0.2.3] Q4 2022
- renamed from ICS-DeviceManagement to omnect github orga

## [0.2.2] Q1 2022
- fix cargo audit warnings by updating/removing dependencies
- disabled failing integration tests

## [0.2.1] Q1 2022
- remove iot-identity-service as submodule and re-add as git dependency
- bump to current main rev (Feb 28, 2022)

## [0.2.0] Q1 2022
- Downgrade to rust cargo edition 2018, due to cargo-bitbake 0.3.15 is not supporting edition 2021

## [0.1.0] Q4 2021
- Initial Version
