import Foundation
import CryptoKit

enum FastDNSCryptoError: Error {
    case invalidHex
    case invalidKeyLength
    case decryptionFailed
    case invalidData
    case base32EncodingFailed
}

public struct FastDNSCrypto {
    // Extracted Master Key from libfvpnkeys.so NativeKeys.masterKey()
    public static let masterKeyHex = "3529de18502ac35a534ce8b541d834228ca3c1cd89b6ce3d31cf44072f0e477a"
    public static let defaultSubId = "4db6aa8190671ed0"
    public static let defaultInstallId = "73f7f016233cf06ab0eeeea89e0ec50c"
    public static let certHex = "c39a8841ecb915f1ba6462f486ee009219b052db290f5209f53d34c31c56ab41"

    public static func dataFromHex(_ hex: String) -> Data? {
        var data = Data()
        var temp = ""
        for char in hex {
            temp.append(char)
            if temp.count == 2 {
                guard let byte = UInt8(temp, radix: 16) else { return nil }
                data.append(byte)
                temp = ""
            }
        }
        return data
    }

    public static func hmacSHA256(key: Data, data: Data) -> Data {
        let symKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symKey)
        return Data(mac)
    }

    public static func deriveSubKey(subId: String) -> Data {
        let mKey = dataFromHex(masterKeyHex)!
        let subData = subId.data(using: .utf8)!
        return hmacSHA256(key: mKey, data: subData)
    }

    public static func deriveHandshakeKey(subKey: Data, installId: String) -> Data {
        var msg = Data()
        msg.append("hs1".data(using: .utf8)!)
        msg.append(0x00)
        msg.append(installId.data(using: .utf8)!)
        msg.append(0x00)
        msg.append(certHex.data(using: .utf8)!)
        return hmacSHA256(key: subKey, data: msg)
    }

    public static func deriveSessionKey(subKey: Data, installId: String, sid: String) -> Data {
        var msg = Data()
        msg.append(installId.data(using: .utf8)!)
        msg.append(0x00)
        msg.append(sid.data(using: .utf8)!)
        msg.append(0x00)
        msg.append(certHex.data(using: .utf8)!)
        return hmacSHA256(key: subKey, data: msg)
    }

    public static func aesGCMDecrypt(key: Data, iv: Data, ciphertextAndTag: Data) throws -> Data {
        guard ciphertextAndTag.count >= 16 else {
            throw FastDNSCryptoError.invalidData
        }
        let symKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: iv)
        let ct = ciphertextAndTag.dropLast(16)
        let tag = ciphertextAndTag.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: symKey)
    }

    public static func aesGCMEncrypt(key: Data, iv: Data, plaintext: Data) throws -> Data {
        let symKey = SymmetricKey(data: key)
        let nonce = try AES.GCM.Nonce(data: iv)
        let box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce)
        return box.ciphertext + box.tag
    }

    // RFC 4648 Base32 implementation (lowercase without padding for DNS labels)
    private static let base32Chars = Array("abcdefghijklmnopqrstuvwxyz234567")

    public static func base32Encode(_ data: Data) -> String {
        var result = ""
        var buffer: UInt32 = 0
        var bitsLeft = 0

        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                bitsLeft -= 5
                let index = Int((buffer >> bitsLeft) & 0x1F)
                result.append(base32Chars[index])
            }
        }

        if bitsLeft > 0 {
            let index = Int((buffer << (5 - bitsLeft)) & 0x1F)
            result.append(base32Chars[index])
        }

        return result
    }
}
