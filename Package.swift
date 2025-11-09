// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-bcrypt-pbkdf",
    platforms: [
        .macOS(.v13), .iOS(.v15)
    ],
    products: [
        .library(
            name: "swift-bcrypt-pbkdf",
            targets: ["swift-bcrypt-pbkdf"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.2.0")
    ],
    targets: [
        .target(
            name: "swift-bcrypt-pbkdf",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(
            name: "swift-bcrypt-pbkdfTests",
            dependencies: ["swift-bcrypt-pbkdf"]
        ),
    ]
)
