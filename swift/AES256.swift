//
//  AES256.swift
//  DecryprionTest
//
//  Created by Andrew Yaniv on 3/29/19.
//  Copyright © 2019 Project Core Inc. All rights reserved.
//

import Foundation
import CommonCrypto

class AES256 {
    
    func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        
        let outputLength = data.count + kCCBlockSizeAES128
        var outputBuffer = Array<UInt8>(repeating: 0, count: outputLength)
        var numBytesEncrypted = 0
        
        let status = CCCrypt(CCOperation(kCCEncrypt),
                             CCAlgorithm(kCCAlgorithmAES),
                             CCOptions(kCCOptionPKCS7Padding),
                             Array(key),
                             kCCKeySizeAES256,
                             Array(iv),
                             Array(data),
                             data.count,
                             &outputBuffer,
                             outputLength,
                             &numBytesEncrypted)
        
        guard status == kCCSuccess else {
            throw Error.encryptionFailed(status: status)
        }
        
        let outputBytes = iv + outputBuffer.prefix(numBytesEncrypted)
        return Data(outputBytes)
    }
    
    func decrypt(data cipherData: Data, key: Data, iv: Data) throws -> Data {
        
        let ivBlock = iv.prefix(kCCBlockSizeAES128)
        let cipherTextBytes = cipherData
            .suffix(from: kCCBlockSizeAES128)
        let cipherTextLength = cipherTextBytes.count
        var outputBuffer = Array<UInt8>(repeating: 0, count: cipherTextLength)
        var numBytesDecrypted = 0
        
        let status = CCCrypt(CCOperation(kCCDecrypt),
                             CCAlgorithm(kCCAlgorithmAES),
                             CCOptions(kCCOptionPKCS7Padding),
                             Array(key),
                             kCCKeySizeAES256,
                             Array(ivBlock),
                             Array(cipherTextBytes),
                             cipherTextLength,
                             &outputBuffer,
                             cipherTextLength,
                             &numBytesDecrypted)
        
        guard status == kCCSuccess else {
            throw Error.decryptionFailed(status: status)
        }
        
        let outputBytes = outputBuffer.prefix(numBytesDecrypted)
        return Data(outputBytes)
    }
    
    func derivateKey(passphrase: Data, salt: Data) throws -> Data {
        var salted: Data = Data()
        
        var dxData = Data()
        
        while salted.count < 48 {
            let data: Data = dxData + passphrase + salt
            
            dxData = md5(data)
            
            salted = salted + dxData
        }
        
        return salted
    }
    
    private func md5(_ inputData: Data) -> Data {
        var digestData = Data(count: Int(CC_MD5_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes {digestBytes in
            inputData.withUnsafeBytes {messageBytes in
                CC_MD5(messageBytes, CC_LONG(inputData.count), digestBytes)
            }
        }
        
        return digestData
    }
    
}

private enum Error: Swift.Error {
    case keyDerivationFailed(status: CCCryptorStatus)
    case encryptionFailed(status: CCCryptorStatus)
    case decryptionFailed(status: CCCryptorStatus)
}

private extension Data {
    
    var hexString: String? {
        return withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            let charA = UInt8(UnicodeScalar("a").value)
            let char0 = UInt8(UnicodeScalar("0").value)
            
            func itoh(_ value: UInt8) -> UInt8 {
                return (value > 9) ? (charA + value - 10) : (char0 + value)
            }
            
            let hexLen = count * 2
            let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: hexLen)
            
            for i in 0 ..< count {
                ptr[i*2] = itoh((bytes[i] >> 4) & 0xF)
                ptr[i*2+1] = itoh(bytes[i] & 0xF)
            }
            
            return String(bytesNoCopy: ptr,
                          length: hexLen,
                          encoding: .utf8,
                          freeWhenDone: true)
        }
    }
}
