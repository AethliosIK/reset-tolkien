# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.3] - 2024-11-01

### Fixed

- #16: Remove catched exception and fix the real bug: Input timestamps too old have been rejected.

## [1.3.2] - 2024-11-01

### Fixed

- #17: Remove singleton to fix the real bug

## [1.3.1] - 2024-11-01

### Fixed

- #17: Optimize multithreading via singleton for serialized data.
- #16: A non-catched exception for a non-timestamp token in python 3.10.15
- #15: Fix Dockerfile and requirements update by @oddnetwork

## [1.3.0] - 2024-08-13

### Added

- #13: Optimization of the detection of hashed timestamps via multithreading.
- #12: Progress bar for detection of hashed timestamps with `--progress` option.
- #11 (suggested by @Aituglo): Custom MAC for UUID sandwich attack with `--alternative-tokens` option.

## [1.2.0] - 2024-06-30

### Added

- #4: Add argument `--version` in cli to print current version.

### Fixed

- #9: Bug with uniqid if the timestamp contains a zero as last decimal digit.
- #8: Bug with nanosecond in timestamp.
- #7: Error when running the example code provided in the blog post with docker environment.

## [1.1.1] - 2024-04-21

### Fixed

- #5: Fix path of default config file.


## [1.1.0] - 2024-04-13

### Added

- #1: Docker installation by @Nishacid.
- #2: Improve timestamp detection during `detect` process.

## [1.0.0] - 2024-03-29

### Added

- First version released.