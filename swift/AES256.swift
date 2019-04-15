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
    
    func encrypt(input: String, password: String) throws -> String? {
        
        let data = input.data(using: .utf8)!
        
        let passwordData = password.data(using: .utf8)!
        
        let salt = "Labrador".data(using: .utf8)!
        
        let key: Data = try! derivateKey(passphrase: passwordData, salt: salt)
        
        let iv = key[32...47]
        
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
        
        
        let salted = Data("Salted__".utf8)
        
        let saltedWithSalt = salted + salt
        
        let outputBytes = saltedWithSalt + outputBuffer.prefix(numBytesEncrypted)
        
        let encrypted: String = outputBytes.base64EncodedString()
        
        return encrypted
    }
    
    func decrypt(input: String, password: String) throws -> String? {
        
        var inputData = Data(base64Encoded: input)!
        
        if let salted = String(data: inputData[...7], encoding: .utf8) {
            if salted != "Salted__" {
                return nil
            }
        }
        
        let salt: Data = inputData[8...15]
        
        let passwordData = password.data(using: .utf8)!
        
        let key = try! derivateKey(passphrase: passwordData, salt: salt)
        
        let iv = key[32...47]
        
        let ivBlock = iv.prefix(kCCBlockSizeAES128)
        let cipherTextBytes = inputData[16...]
        
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
        
        let outputData: Data = Data(outputBytes)
        if let decryptedText: String = String(data: outputData, encoding: .utf8) {
            return decryptedText
        } else {
            return nil
        }
    }
    
    private func derivateKey(passphrase: Data, salt: Data) throws -> Data {
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
    
    private var hexString: String? {
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
