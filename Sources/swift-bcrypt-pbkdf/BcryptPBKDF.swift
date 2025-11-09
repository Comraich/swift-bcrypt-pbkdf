#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/*
 * bcrypt_pbkdf translated from the OpenBSD reference implementation
 * (Ted Unangst, 2013) and exposed as a Swift API.
 *
 * Publishing checklist:
 *  - Ensure this source file ships with the OpenBSD license text (see LICENSE).
 *  - Reference this module in Package.swift and in your documentation/README.
 *  - Expose usage examples via the doc comments below so DocC / Jazzy can pick them up.
 */
public enum BcryptPBKDFError: Error, Equatable {
    case invalidRoundCount
    case invalidInput
    case keyLengthTooLarge
}

/// High-level API for deriving secret material using the bcrypt-based PBKDF
/// specified by OpenBSD.
///
/// Usage example:
/// ```swift
/// let password = Data("password".utf8)
/// let salt = Data("salt".utf8)
/// let key = try BcryptPBKDF.deriveKey(password: password,
///                                     salt: salt,
///                                     rounds: 8,
///                                     outputLength: 32)
/// ```
/// - Note: The implementation follows the OpenBSD reference semantics,
///         including the non-linear output stride that mitigates
///         the partial-output shortcut issue in PBKDF2.
public enum BcryptPBKDF {
    private static let blockWords = BlowfishConstants.wordCount
    private static let blockSize = BlowfishConstants.hashSize
    private static let maxKeyLength = blockSize * blockSize

    /// Derive key material as `Data`.
    ///
    /// - Parameters:
    ///   - password: Arbitrary binary password bytes (will be SHA-512 hashed internally).
    ///   - salt: Arbitrary binary salt (minimum 1 byte).
    ///   - rounds: Cost parameter (must be ≥ 1). Each additional round re hashes the
    ///             previous block and XORs it into the accumulated output.
    ///   - outputLength: Number of bytes to produce (must be > 0 and ≤ 8 * block size²).
    /// - Returns: Deterministic derived key bytes of the requested length.
    /// - Throws: `BcryptPBKDFError` when parameters are invalid.
    public static func deriveKey(password: Data, salt: Data, rounds: Int, outputLength: Int) throws -> Data {
        let bytes = try deriveKey(
            password: Array(password),
            salt: Array(salt),
            rounds: rounds,
            outputLength: outputLength
        )
        return Data(bytes)
    }

    /// Derive key material as `[UInt8]`. See the `Data` overload for parameter semantics.
    public static func deriveKey(password: [UInt8], salt: [UInt8], rounds: Int, outputLength: Int) throws -> [UInt8] {
        guard rounds >= 1 else { throw BcryptPBKDFError.invalidRoundCount }
        guard !password.isEmpty, !salt.isEmpty, outputLength > 0 else {
            throw BcryptPBKDFError.invalidInput
        }
        guard outputLength <= maxKeyLength else { throw BcryptPBKDFError.keyLengthTooLarge }

        let stride = (outputLength + blockSize - 1) / blockSize
        let amount = (outputLength + stride - 1) / stride

        var shaPass = sha512Digest(of: password)
        defer { shaPass.resetBytes() }

        var derived = [UInt8](repeating: 0, count: outputLength)
        var remaining = outputLength
        var counter: UInt32 = 1

        while remaining > 0 {
            let counterBytes: [UInt8] = [
                UInt8((counter >> 24) & 0xff),
                UInt8((counter >> 16) & 0xff),
                UInt8((counter >> 8) & 0xff),
                UInt8(counter & 0xff)
            ]

            var shaSalt = sha512Digest(concatenating: salt, counterBytes)
            var tmp = bcryptHash(shaPass: shaPass, shaSalt: shaSalt)
            var block = tmp

            for _ in 1..<rounds {
                shaSalt = sha512Digest(of: tmp)
                tmp = bcryptHash(shaPass: shaPass, shaSalt: shaSalt)
                for index in 0..<block.count {
                    block[index] ^= tmp[index]
                }
            }

            let chunk = min(amount, remaining)
            var produced = 0
            for i in 0..<chunk {
                let destination = i * stride + Int(counter - 1)
                if destination >= outputLength {
                    break
                }
                derived[destination] = block[i]
                produced += 1
            }

            remaining -= produced
            counter &+= 1
        }

        return derived
    }

    private static func bcryptHash(shaPass: [UInt8], shaSalt: [UInt8]) -> [UInt8] {
        var state = Blowfish()
        state.reset()
        state.expandState(with: shaSalt, key: shaPass)
        for _ in 0..<64 {
            state.expandKeySchedule(with: shaSalt)
            state.expandKeySchedule(with: shaPass)
        }

        var ciphertext = Array("OxychromaticBlowfishSwatDynamite".utf8)
        var offset = 0
        var words = [UInt32](repeating: 0, count: blockWords)
        for index in 0..<blockWords {
            words[index] = Blowfish.streamToWord(ciphertext, offset: &offset)
        }

        for _ in 0..<64 {
            state.encrypt(words: &words)
        }

        var output = [UInt8](repeating: 0, count: blockSize)
        for index in 0..<blockWords {
            let word = words[index]
            let base = index * 4
            output[base + 3] = UInt8((word >> 24) & 0xff)
            output[base + 2] = UInt8((word >> 16) & 0xff)
            output[base + 1] = UInt8((word >> 8) & 0xff)
            output[base + 0] = UInt8(word & 0xff)
        }

        ciphertext.resetBytes()
        words.resetWords()
        return output
    }

    private static func sha512Digest(of data: [UInt8]) -> [UInt8] {
        return Array(SHA512.hash(data: Data(data)))
    }

    private static func sha512Digest(concatenating first: [UInt8], _ second: [UInt8]) -> [UInt8] {
        var hasher = SHA512()
        hasher.update(data: Data(first))
        hasher.update(data: Data(second))
        return Array(hasher.finalize())
    }
}

private extension Array where Element == UInt8 {
    mutating func resetBytes() {
        _ = self.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
}

private extension Array where Element == UInt32 {
    mutating func resetWords() {
        _ = self.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
}
