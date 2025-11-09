/*
 * Ported from the OpenBSD Blowfish implementation (blowfish.c)
 * Original license: Copyright 1997 Niels Provos.
 */
struct Blowfish {
    private var p: [UInt32]
    private var s: [[UInt32]]

    init() {
        self.p = BlowfishConstants.initialP
        self.s = BlowfishConstants.initialS
    }

    mutating func reset() {
        self.p = BlowfishConstants.initialP
        self.s = BlowfishConstants.initialS
    }

    mutating func expandState(with data: [UInt8], key: [UInt8]) {
        guard !data.isEmpty, !key.isEmpty else { return }

        var keyOffset = 0
        for index in 0..<p.count {
            let word = Blowfish.streamToWord(key, offset: &keyOffset)
            p[index] ^= word
        }

        var dataOffset = 0
        var left: UInt32 = 0
        var right: UInt32 = 0

        for index in stride(from: 0, to: p.count, by: 2) {
            left ^= Blowfish.streamToWord(data, offset: &dataOffset)
            right ^= Blowfish.streamToWord(data, offset: &dataOffset)
            encipher(left: &left, right: &right)
            p[index] = left
            p[index + 1] = right
        }

        for box in 0..<s.count {
            for entry in stride(from: 0, to: s[box].count, by: 2) {
                left ^= Blowfish.streamToWord(data, offset: &dataOffset)
                right ^= Blowfish.streamToWord(data, offset: &dataOffset)
                encipher(left: &left, right: &right)
                s[box][entry] = left
                s[box][entry + 1] = right
            }
        }
    }

    mutating func expandKeySchedule(with key: [UInt8]) {
        guard !key.isEmpty else { return }

        var keyOffset = 0
        for index in 0..<p.count {
            let word = Blowfish.streamToWord(key, offset: &keyOffset)
            p[index] ^= word
        }

        var left: UInt32 = 0
        var right: UInt32 = 0

        for index in stride(from: 0, to: p.count, by: 2) {
            encipher(left: &left, right: &right)
            p[index] = left
            p[index + 1] = right
        }

        for box in 0..<s.count {
            for entry in stride(from: 0, to: s[box].count, by: 2) {
                encipher(left: &left, right: &right)
                s[box][entry] = left
                s[box][entry + 1] = right
            }
        }
    }

    mutating func encrypt(words: inout [UInt32]) {
        precondition(words.count % 2 == 0, "Blowfish encryption requires pairs of words")
        var index = 0
        while index < words.count {
            var left = words[index]
            var right = words[index + 1]
            encipher(left: &left, right: &right)
            words[index] = left
            words[index + 1] = right
            index += 2
        }
    }

    private mutating func encipher(left: inout UInt32, right: inout UInt32) {
        var xl = left
        var xr = right

        xl ^= p[0]
        for round in 1...16 {
            if round % 2 == 1 {
                xr ^= roundFunction(xl) ^ p[round]
            } else {
                xl ^= roundFunction(xr) ^ p[round]
            }
        }

        left = xr ^ p[17]
        right = xl
    }

    @inline(__always)
    private func roundFunction(_ value: UInt32) -> UInt32 {
        let a = s[0][Int((value >> 24) & 0xff)]
        let b = s[1][Int((value >> 16) & 0xff)]
        let c = s[2][Int((value >> 8) & 0xff)]
        let d = s[3][Int(value & 0xff)]
        return ((a &+ b) ^ c) &+ d
    }

    static func streamToWord(_ data: [UInt8], offset: inout Int) -> UInt32 {
        guard !data.isEmpty else { return 0 }
        var word: UInt32 = 0
        var idx = offset
        for _ in 0..<4 {
            if idx >= data.count {
                idx = 0
            }
            word = (word << 8) | UInt32(data[idx])
            idx += 1
        }
        offset = idx
        return word
    }
}
