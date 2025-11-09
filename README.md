# swift-bcrypt-pbkdf

A pure Swift implementation of the OpenBSD bcrypt-based PBKDF, suitable for deriving encryption keys from passwords. The implementation faithfully ports the Blowfish primitives and the modified PBKDF2 flow introduced by the OpenBSD `bcrypt_pbkdf` function.

## Features

- SHA-512 pre-processing followed by 64-round EksBlowfish expansion as specified by OpenBSD
- Supports arbitrary password/salt data (`Data` or `[UInt8]`)
- Enforces the OpenBSD non-linear output shuffle to avoid partial-output shortcuts
- Unit-tested against the published vectors from PyCA/bcrypt (ASCII, NUL-containing, UTF-8 inputs)
- Works on macOS and iOS via `swift-crypto` for cross-platform SHA-512 fallback

## Installation

Add the package to your `Package.swift` dependencies (Swift 6.2 or later):

```swift
let package = Package(
    dependencies: [
        .package(url: "https://github.com/Comraich/swift-bcrypt-pbkdf.git", from: "0.1.0")
    ],
    targets: [
        .target(
            name: "YourTarget",
            dependencies: [
                .product(name: "swift-bcrypt-pbkdf", package: "swift-bcrypt-pbkdf")
            ]
        )
    ]
)
```

Then import the module:

```swift
import swift_bcrypt_pbkdf
```

## Usage

```swift
import swift_bcrypt_pbkdf

let password = Data("correct horse battery staple".utf8)
let salt = Data("unique-salt".utf8)
let rounds = 10
let derivedKey = try BcryptPBKDF.deriveKey(password: password,
                                          salt: salt,
                                          rounds: rounds,
                                          outputLength: 32)
```

### Parameter guidelines

- `password`: any non-empty byte sequence. Both `Data` and `[UInt8]` overloads are provided.
- `salt`: any non-empty byte sequence. Longer salts provide better collision resistance.
- `rounds`: must be ≥ 1. Increase to raise CPU cost (e.g. 10–20 for interactive logins; higher for offline derivations).
- `outputLength`: number of bytes required. The implementation enforces the specification limit (`≤ 8 * 32^2`).

## Testing

Run the built-in XCTest suite:

```bash
swift test
```

The `BcryptPBKDFTests` suite validates the implementation against the PyCA/bcrypt KDF vectors and covers invalid parameter handling.

## License

Portions of this work are derived from the OpenBSD Blowfish (`blowfish.c`, `blf.h`) and `bcrypt_pbkdf.c` sources. Their original BSD-style licenses are reproduced in [LICENSE](LICENSE). The Swift code in this repository is made available under the same terms.
