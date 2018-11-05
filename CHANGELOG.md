# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Fixed

- IPv4/UInt32 conversions are not endianness-agnostic. [#46](https://github.com/keeshux/tunnelkit/pull/46)

## 1.3.0 (2018-10-28)

### Changed

- Refactored tunnel configuration API for increased code reuse. [#44](https://github.com/keeshux/tunnelkit/pull/44)

### Deprecated

- Use high-level accessories instead of `debugLogKey` and `lastErrorKey`. [#45](https://github.com/keeshux/tunnelkit/pull/45)

### Fixed

- IPv4/UInt32 calculations were wrong.

## 1.2.2 (2018-10-25)

### Changed

- Debug log is saved to group container rather than `UserDefaults`. [#43](https://github.com/keeshux/tunnelkit/pull/43)

### Fixed

- Handle server-initiated renegotiation. [#41](https://github.com/keeshux/tunnelkit/pull/41)
- Potentially private data (e.g. Internet addresses) is now masked in debug log. [#42](https://github.com/keeshux/tunnelkit/pull/42)

## 1.2.1 (2018-10-24)

### Added

- Configuration key `lastErrorKey` for reporting errors to host app. [#40](https://github.com/keeshux/tunnelkit/pull/40)
- Server extended key usage validation (EKU). [#27](https://github.com/keeshux/tunnelkit/issues/27)

### Fixed

- CA file was not closed after MD5 calculation when using PIA patches.
- Mitigated an issue with MTU in TCP mode during negotiation. [#39](https://github.com/keeshux/tunnelkit/issues/39)

## 1.2.0 (2018-10-20)

### Added

- Support for `--tls-auth` wrapping. [#34](https://github.com/keeshux/tunnelkit/pull/34)
- Support for `--tls-crypt` wrapping. [#35](https://github.com/keeshux/tunnelkit/pull/35)
- Parser for static OpenVPN keys from file. [#36](https://github.com/keeshux/tunnelkit/pull/36)

### Fixed

- Handling of mixed DATA_V1/DATA_V2 packets. [#30](https://github.com/keeshux/tunnelkit/issues/30)

## 1.1.2 (2018-10-18)

### Added

- Restored support for PIA patches. [#32](https://github.com/keeshux/tunnelkit/pull/32)

## 1.1.1 (2018-10-10)

### Fixed

- Make CA non-optional. [#28](https://github.com/keeshux/tunnelkit/pull/28)

## 1.1.0 (2018-09-26)

### Added

- Client certificate verification. [#3](https://github.com/keeshux/tunnelkit/pull/3)
- Support for both `--comp-lzo` and `--compress` compression framing. [#2](https://github.com/keeshux/tunnelkit/pull/2), [#5](https://github.com/keeshux/tunnelkit/pull/5), [#10](https://github.com/keeshux/tunnelkit/pull/10)
- Routes setup from PUSH_REPLY. [#7](https://github.com/keeshux/tunnelkit/pull/7)
- Support for IPv6. [#8](https://github.com/keeshux/tunnelkit/pull/8)
- Support for server-side NCP. [#11](https://github.com/keeshux/tunnelkit/pull/11)
- Property to mark ciphers not requiring digest auth (e.g. GCM). [#13](https://github.com/keeshux/tunnelkit/pull/13)
- `Codable` implementations for native Swift serialization. [#15](https://github.com/keeshux/tunnelkit/pull/15)
- More cipher and digest algorithms. [#16](https://github.com/keeshux/tunnelkit/pull/16)
- Negotiated compression framing from PUSH_REPLY. [#19](https://github.com/keeshux/tunnelkit/pull/19)
- Customizable keep-alive. [#20](https://github.com/keeshux/tunnelkit/pull/20)
- Negotiated keep-alive from PUSH_REPLY. [#22](https://github.com/keeshux/tunnelkit/pull/22)
- Peer-info metadata.

### Changed

- Raised iOS target to 11 (drops 32-bit support).
- Upgraded OpenSSL from 1.1.0h to 1.1.0i.
- Minor adjustments for Xcode 10 / Swift 4.2.
- Deep refactoring of control channel for future extensibility.
- App group moved out of tunnel configuration, to make it more platform-agnostic and coherent to serialize.
- Keep-alive is disabled by default.
- Several internal renamings.

### Fixed

- Sensitive data logged in PUSH_REPLY. [#12](https://github.com/keeshux/tunnelkit/pull/12)
- Bad interpretation of 0 seconds between renegotiations. [#18](https://github.com/keeshux/tunnelkit/pull/18)
- Incorrect behavior on data-related failures. [#21](https://github.com/keeshux/tunnelkit/pull/21)

## 1.0.0 (2018-08-23)

### Added

- Initial fork from https://github.com/pia-foss/tunnel-apple

### Removed

- Non-standard PIA patches.
