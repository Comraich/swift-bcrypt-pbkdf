import Foundation
import XCTest
@testable import swift_bcrypt_pbkdf

final class BcryptPBKDFTests: XCTestCase {
    func testKnownVectors() throws {
        struct Vector {
            let rounds: Int
            let password: [UInt8]
            let salt: [UInt8]
            let expected: [UInt8]
        }

        let asciiPassword = Array("password".utf8)
        let asciiSalt = Array("salt".utf8)

        let vectors: [Vector] = [
            Vector(
                rounds: 4,
                password: asciiPassword,
                salt: asciiSalt,
                expected: [
                    0x5b, 0xbf, 0x0c, 0xc2, 0x93, 0x58, 0x7f, 0x1c,
                    0x36, 0x35, 0x55, 0x5c, 0x27, 0x79, 0x65, 0x98,
                    0xd4, 0x7e, 0x57, 0x90, 0x71, 0xbf, 0x42, 0x7e,
                    0x9d, 0x8f, 0xbe, 0x84, 0x2a, 0xba, 0x34, 0xd9
                ]
            ),
            Vector(
                rounds: 4,
                password: asciiPassword,
                salt: [0x00],
                expected: [
                    0xc1, 0x2b, 0x56, 0x62, 0x35, 0xee, 0xe0, 0x4c,
                    0x21, 0x25, 0x98, 0x97, 0x0a, 0x57, 0x9a, 0x67
                ]
            ),
            Vector(
                rounds: 8,
                password: asciiPassword,
                salt: asciiSalt,
                expected: [
                    0xe1, 0x36, 0x7e, 0xc5, 0x15, 0x1a, 0x33, 0xfa,
                    0xac, 0x4c, 0xc1, 0xc1, 0x44, 0xcd, 0x23, 0xfa,
                    0x15, 0xd5, 0x54, 0x84, 0x93, 0xec, 0xc9, 0x9b,
                    0x9b, 0x5d, 0x9c, 0x0d, 0x3b, 0x27, 0xbe, 0xc7,
                    0x62, 0x27, 0xea, 0x66, 0x08, 0x8b, 0x84, 0x9b,
                    0x20, 0xab, 0x7a, 0xa4, 0x78, 0x01, 0x02, 0x46,
                    0xe7, 0x4b, 0xba, 0x51, 0x72, 0x3f, 0xef, 0xa9,
                    0xf9, 0x47, 0x4d, 0x65, 0x08, 0x84, 0x5e, 0x8d
                ]
            ),
            Vector(
                rounds: 8,
                password: [
                    0xe1, 0xbd, 0x88, 0xce, 0xb4, 0xcf, 0x85, 0xcf,
                    0x83, 0xcf, 0x83, 0xce, 0xb5, 0xcf, 0x8d, 0xcf,
                    0x82
                ],
                salt: [
                    0xce, 0xa4, 0xce, 0xb7, 0xce, 0xbb, 0xce, 0xad,
                    0xce, 0xbc, 0xce, 0xb1, 0xcf, 0x87, 0xce, 0xbf,
                    0xcf, 0x82
                ],
                expected: [
                    0x43, 0x66, 0x6c, 0x9b, 0x09, 0xef, 0x33, 0xed,
                    0x8c, 0x27, 0xe8, 0xe8, 0xf3, 0xe2, 0xd8, 0xe6
                ]
            )
        ]

        for vector in vectors {
            let key = try BcryptPBKDF.deriveKey(
                password: Data(vector.password),
                salt: Data(vector.salt),
                rounds: vector.rounds,
                outputLength: vector.expected.count
            )
            XCTAssertEqual(Array(key), vector.expected)
        }
    }

    func testInvalidParameters() {
        XCTAssertThrowsError(
            try BcryptPBKDF.deriveKey(
                password: Data(),
                salt: Data("salt".utf8),
                rounds: 4,
                outputLength: 16
            )
        ) { error in
            XCTAssertEqual(error as? BcryptPBKDFError, .invalidInput)
        }

        XCTAssertThrowsError(
            try BcryptPBKDF.deriveKey(
                password: Data("password".utf8),
                salt: Data("salt".utf8),
                rounds: 0,
                outputLength: 16
            )
        ) { error in
            XCTAssertEqual(error as? BcryptPBKDFError, .invalidRoundCount)
        }

        XCTAssertThrowsError(
            try BcryptPBKDF.deriveKey(
                password: Data("password".utf8),
                salt: Data("salt".utf8),
                rounds: 4,
                outputLength: 2048
            )
        ) { error in
            XCTAssertEqual(error as? BcryptPBKDFError, .keyLengthTooLarge)
        }
    }
}
