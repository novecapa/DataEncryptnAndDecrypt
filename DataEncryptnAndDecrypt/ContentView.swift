//
//  ContentView.swift
//  DataEncryptnAndDecrypt
//
//  Created by Josep Cerdá Penadés on 15/7/24.
//

import CommonCrypto
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {

    private enum Constants {
        static let encryptKey: String = "Qg$GsCcE=_WWpIzR4+0I0DlofLpq1_7fC"
        static let pskExt: String = "psk"
    }

    @State private var text = ""
    @State private var error: Error?
    @State private var isImporting = false
    @State private var selectedFileURL: URL?
    @State private var isExporting = false

    var body: some View {
        VStack {
            Button(action: {
                isImporting.toggle()
            }, label: {
                Text("Select a file")
            })
        }
        .fileImporter(isPresented: $isImporting,
                      allowedContentTypes: [
                        .jpeg,
                        .png,
                        .pdf,
                        .init(filenameExtension: "pages")!,
                        .init(filenameExtension: Constants.pskExt)!
                      ],
                      allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    do {
                        try decryptFile(atPath: url, withKey: Constants.encryptKey)
                        // try encryptFile(atPath: url, withKey: Constants.encryptKey)
                    } catch {
                        print("Error: \(error.localizedDescription)")
                    }
                }
            case .failure(let error):
                print("File import failed with error: \(error.localizedDescription)")
            }
        }
    }

    private func encrypt(data: Data, key: String) -> Data? {
        let keyData = key.data(using: .utf8)!
        let inputData = data as NSData
        let encryptedData = NSMutableData(length: Int(inputData.length) + kCCBlockSizeAES128)!
        let keyLength = size_t(kCCKeySizeAES128)
        let operation = CCOperation(kCCEncrypt)
        let algorithm = CCAlgorithm(kCCAlgorithmAES)
        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let cryptStatus = CCCrypt(
            operation,
            algorithm,
            options,
            (keyData as NSData).bytes, keyLength,
            nil,
            inputData.bytes, inputData.length,
            encryptedData.mutableBytes, encryptedData.length,
            &numBytesEncrypted
        )

        if cryptStatus == kCCSuccess {
            encryptedData.length = Int(numBytesEncrypted)
            return encryptedData as Data
        }

        return nil
    }

    func encryptFile(atPath fileURL: URL, withKey key: String) throws {
        let fileData = try Data(contentsOf: fileURL)
        guard let encryptedData = encrypt(data: fileData, key: key) else {
            throw NSError(domain: "EncryptionError", code: -1, userInfo: nil)
        }

        let encryptedFile = "\(fileURL.path(percentEncoded: false)).\(Constants.pskExt)"
        try encryptedData.write(to: URL(filePath: encryptedFile), options: .atomic)
        print("File encrypted successfully.")
    }

    private func decrypt(data: Data, key: String) -> Data? {
        let keyData = key.data(using: .utf8)!
        let inputData = data as NSData
        let decryptedData = NSMutableData(length: Int(inputData.length) + kCCBlockSizeAES128)!
        let keyLength = size_t(kCCKeySizeAES128)
        let operation = CCOperation(kCCDecrypt)
        let algorithm = CCAlgorithm(kCCAlgorithmAES)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = CCCrypt(
            operation,
            algorithm,
            options,
            (keyData as NSData).bytes, keyLength,
            nil,
            inputData.bytes, inputData.length,
            decryptedData.mutableBytes, decryptedData.length,
            &numBytesDecrypted
        )
        
        if cryptStatus == kCCSuccess {
            decryptedData.length = Int(numBytesDecrypted)
            return decryptedData as Data
        }
        
        return nil
    }

    func decryptFile(atPath fileURL: URL, withKey key: String) throws {
        let fileData = try Data(contentsOf: fileURL)
        guard let decryptedData = decrypt(data: fileData, key: key) else {
            throw NSError(domain: "DecryptionError", code: -1, userInfo: nil)
        }
        let decryptedFile = fileURL.path.replacingOccurrences(of: ".psk", with: "")
        try decryptedData.write(to: URL(filePath: decryptedFile), options: .atomic)
        print("File decrypted successfully.")
    }
}

#Preview {
    ContentView()
}
