import Flutter
import Alamofire
import CommonCrypto

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    let manager = Alamofire.SessionManager.default
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch (call.method) {
            case "check":
                if let _args = call.arguments as? Dictionary<String, AnyObject> {
                    self.check(call: call, args: _args, flutterResult: result)
                } else {
                    result(
                        FlutterError(
                            code: "Invalid Arguments",
                            message: "Please specify arguments",
                            details: nil)
                    )
                }
                break
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    public func check(
        call: FlutterMethodCall,
        args: Dictionary<String, AnyObject>,
        flutterResult: @escaping FlutterResult
    ){
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? Dictionary<String, String>,
              let fingerprints = args["fingerprints"] as? Array<String>,
              let type = args["type"] as? String
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "Les params sont incorrect",
                    details: nil
                )
            )
            return
        }

        self.fingerprints = fingerprints

        var timeout = 60
        if let timeoutArg = args["timeout"] as? Int {
            timeout = timeoutArg
        }
        
        let manager = Alamofire.SessionManager(
            configuration: URLSessionConfiguration.default
        )
        
        var resultDispatched = false;
        
        manager.session.configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        
        manager.request(urlString, method: .get, parameters: headers).validate().responseJSON() { response in
            switch response.result {
                case .success:
                    break
            case .failure(let error):
                if (!resultDispatched) {
                    flutterResult(
                        FlutterError(
                            code: "URL Format",
                            message: error.localizedDescription,
                            details: nil
                        )
                    )
               }
                   
                break
            }
            
            // To retain
            let _ = manager
        }

        manager.delegate.sessionDidReceiveChallenge = { session, challenge in
            guard let serverTrust = challenge.protectionSpace.serverTrust else {
                flutterResult(
                    FlutterError(
                        code: "ERROR CERT",
                        message: "Invalid Certificate",
                        details: nil
                    )
                )
                return (.cancelAuthenticationChallenge, nil)
            }
            
            // Set SSL policies for domain name check
            let policies = NSMutableArray()
            policies.add(SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString)))
            SecTrustSetPolicies(serverTrust, policies)
            
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            if(isServerTrusted) {
                guard let certificates = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] else {
                    flutterResult(
                        FlutterError(
                            code: "ERROR CERT",
                            message: "Invalid Certificate",
                            details: nil
                        )
                    )

                    return (.cancelAuthenticationChallenge, nil)
                }
                
                // For certificate Key
                //let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
                // let remoteCertData = SecCertificateCopyData(serverCertificate) as Data
                // var certificateKey = remoteCertData.sha256().toHexString()
                
                /*
                let publicKeyList = Set( certificates.map { SecCertificateCopyKey($0)  } )
                publicKeyList.forEach { secKey in
                    if let secKey = secKey, let publicKeyData = SecKeyCopyExternalRepresentation(secKey, nil) as? Data {
                        let keyString = self.sha256(data: publicKeyData)
                        print(keyString)
                    }
                }
                 */
                
                var isSecure = false
                
                if let secKey = SecCertificateCopyKey(certificates[0]) , let publicKeyData = SecKeyCopyExternalRepresentation(secKey, nil) as? Data {
                    let keyString = self.sha256(data: publicKeyData)
                    print(keyString)

                    if var fp = self.fingerprints {
                        fp = fp.compactMap { (val) -> String? in
                            val.replacingOccurrences(of: " ", with: "")
                        }
                        isSecure = fp.contains(where: { (value) -> Bool in
                            value.caseInsensitiveCompare(keyString) == .orderedSame
                        })
                    }
                }
                else {
                    flutterResult(
                        FlutterError(
                            code: "ERROR CERT",
                            message: "Invalid Public Key",
                            details: nil
                        )
                    )
                    return (.cancelAuthenticationChallenge, nil)
                }
                
                if isServerTrusted && isSecure {
                    flutterResult("CONNECTION_SECURE")
                    resultDispatched = true
                } else {
                    flutterResult(
                        FlutterError(
                            code: "CONNECTION_NOT_SECURE",
                            message: nil,
                            details: nil
                        )
                    )
                    resultDispatched = true
                }

            }
            
            return (.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func sha256(data : Data) -> String {
        let rsa2048Asn1Header:[UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]

        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            // _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash) // deprecated withUnsafeBytes
            guard let pointer = $0.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            _ = CC_SHA256(pointer, CC_LONG(keyWithHeader.count), &hash)
        }
//        return Data(hash).base64EncodedString()
        return Data(hash).toHexString()

        }

}

extension Data {
     func toHexString() -> String {
        return String(self.flatMap { byte in
            String(format:"%02x", byte)
        })
    }
}

