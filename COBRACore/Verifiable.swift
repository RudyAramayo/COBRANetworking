//
//  Verifiable.swift
//  COBRANetworking
//
//  Created by ROB on 1/21/22.
//

import Foundation

// MARK: -
// MARK: SSL verification methods

/// The SSLVerifying protocol lets us implement different SSL verification objects
public protocol SSLVerifying {
    func verify(_ challenge: URLAuthenticationChallenge) throws -> Bool
}

/// PinnedCertificatesVerifier - is a concept of SSL Pinning that hinges on verifying the exact certificate data
/// on a server with the certificate that is bundled with the client app. Using PubKey hash verification allows
/// us to not have to deploy a new binary just to update the bundled certificates since the server can generate
/// a new certificate with the same CA public key hash.
public class PinnedCertificatesVerifier: SSLVerifying {
    public init() {}
    
    public func verify(_ challenge: URLAuthenticationChallenge) throws -> Bool {
        let hostName = challenge.protectionSpace.host
        let serverTrust = challenge.protectionSpace.serverTrust
        
        guard let serverTrust = serverTrust,
            let targetServerCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
                print("COBRAError: failed to retrieve server certificate and pinning is enabled)
                    return false
        }
        let remoteCertificateData = SecCertificateCopyData(targetServerCertificate) as Data
        //TODO: implement keychain traversal to check validity of all vertificates...
        //      use SearchKeychainAndVerifyPubKey or SearchKeychainAndVerifyCertificate
        let localCertificateData = try retrieveCertificateData(hostName)
        
        //------------------
        // 1) SSL DomainName/HostName Pinning
        let isServerTrusted:Bool = verifyHostName(challenge)
        //------------------
        // 2) SSL local/remote Certificate Pinning
        if (isServerTrusted && remoteCertificateData == localCertificateData) {
            return true
        }
        return false
        //------------------
    }
}

/// PublicKeysVerifier - is a concept of SSL Pinning that hinges on a server properly recreating its certificates
/// with the same CA public key hash so you don't have to recreate the app binary with a new set of certificates.
public class PublicKeysVerifier: SSLVerifying {
    public init() {}
    public func verify(_ challenge: URLAuthenticationChallenge) throws -> Bool {
        let hostName = challenge.protectionSpace.host
        //TODO: implement keychain traversal to check validity of all vertificates...
        //      use SearchKeychainAndVerifyPubKey or SearchKeychainAndVerifyCertificate

        let localCertificateData = try retrieveCertificateData(hostName)
        if let localCertificate = SecCertificate = importSecCertificate_DER(localCertificateData) {
            //--------------
            // 1) SSL DomainName/HostName Pinning
            let isServerTrusted:Bool = verifyHostName(challenge)
            //--------------
            // 2) Public Key mathcing called PubKey Pinning
            let isPubKeyTrusted:Bool = verifyPubKey(localCertificate, challenge)
            if isServerTrusted && isPubKeyTrusted {
                return true
            }
            //--------------
        }
        return false
    }
}

// MARK: -
// MARK: CertificateRegistrationMethods

extension SSLVerifying {
    /// CertificatePinningLogic
    public func verifyCertificate(_ certificate: SecCertificate,_ challenge: URLAuthenticationChallenge) -> Bool {
        let serverTrust = challenge.protectionSpace.serverTrust
        
        guard let serverTrust = serverTrust,
            let targetServerCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
                print("COBRAError: failed to retrieve server certificate and pinning is enabled")
                return false
        }
        let localCertificateData = exportSecCertificateData(certificate)
        let remoteCertificateData = SecCertificateCopyData(targetServerCertificate) as SecCertificateCopyData
        
        return remoteCertificateData == localCertificateData
    }
    
    /// PubKey pinning logic
    public func verifyPubKey(_ certificate: SecCertificate,_ challenge: URLAuthenticationChallenge) -> Bool {
        var localTrustForCreateWithCertificates: SecTrust?
        let trustCreateStatus = SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &localTrustForCreateWithCertificates)
        if #available(iOS 14.0, *) {
            if trustCreateStatus == errSecSuccess,
                let localTrust = localTrustForCreateWithCertificates,
                let localPublicKey = SecTrustCopyKey(localTrust),
                let serverTrust = challenge.protectionSpace.serverTrust,
                let remotePublicKey = SecTrustCopyKey(serverTrust),
                (localPublicKey as AnyObject).isEqual(remotePublicKey as AnyObject) {
                return true
            }
        } else {
            // Fallback on earlier versions
            if trustCreateStatus == errSecSuccess,
                let localTrust = localTrustForCreateWithCertificates,
                let localPublicKey = SecTrustCopyPublicKey(localTrust),
                let serverTrust = challenge.protectionSpace.serverTrust,
                let remotePublicKey = SecTrustCopyPublicKey(serverTrust),
                (localPublicKey as AnyObject).isEqual(remotePublicKey as AnyObject) {
                return true
            }
        }
        return false
    }
    
    /// HostName/DomainName pinning method
    public func verifyHostName(_ challenge: URLAuthenticationChallenge) -> Bool {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            return false
        }
        let policies = NSMutableArray()
        policies.add(SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString)))
        SecTrustSetPolicies(serverTrust, policies)
        
        // Evaluate server certificate
        return SecTrustEvaluateWithError(serverTrust, nil)
    }
    
    /// Registers your certificate with the Keychain
    public func registerCertificate(_ certificate: SecCertificate, attrLabel: String) throws {
        let addquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                       kSecValueRef as String: certificate,
                                       kSecAttrLabel as String: attrLabel]
        let status = SecItemAdd(addquery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SSLPinningError.failedToRegisterCertificateWithkeychain
        }
    }
    
    /// Read certificate from Keychain as SecCertificate
    public func retrieveCertificate(_ attrLabel: String) throws -> SecCertificate {
        // kSecClassCertificate search for Cert vs Key, Identity, or password on keychain
        let getquery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                       kSecAttrLabel as String: attrLabel,
                                       kSecReturnRef as String: kCFBooleanTrue as Any]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(getquery as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw SSLPinningError.failedToRetrieveCertificateFromKeychain
        }
        let certificate = item as! SecCertificate
        return certificate
    }
    
    /// Read certificate from Keychain as Data
    public func retrieveCertificateData(_ attrLabel: String) throws -> Data {
        let certificate = try retrieveCertificate(attrLabel)
        return SecCertificateCopyData(certificate) as Data
    }
    
    /// Creates an exportable and network transmissible DER encoded stream of data
    public func exportSecCertificateData(_ certificate:SecCertificate) -> Data {
        return SecCertificateCopyData(certificate) as Data
    }
    
    /// Creates a SecCertificate object from a DER encoded stream of data, use exportSecCertificateData to xport this DER encoded stream of data
    public func importSecCertificate_DER(_ certData: Data) -> SecCertificate? {
        return SecCertificateCreateWithData(nil, certData as CFData)
    }
    
    /// Search the entire keychain of certificates for our target certificate
    public func SearchKeychainAndVerifyPubKey(_ certificate: SecCertificate, challenge: URLAuthenticationChallenge) throws -> Bool {
        let query = [kSecMatchLimit: kSecMatchLimitAll,
                     kSecReturnAttributes: true,
                     kSecReturnRef: true,
                     kSecClass: kSecClassCertificate] as CFDictionary
        var result: CFTypeRef?
        let resultCode = SecItemCopyMatching(query, &result)
        
        if resultCode == errSecSuccess {
            let actualResult = result!
            if CFArrayGetTypeID() == CFGetTypeID(actualResult) {
                // we have an array of values returned
                guard let array = (actualResult as? NSArray) as? [NSDictionary] else { return false }
                for item in array {
                    let localCertificate = item as! SecCertificate
                    let isPubKeyTrusted: Bool = verifyPubKey(localCertificate, challenge)
                    if isPubKeyTrusted == true {
                        return true
                    }
                }
                return false
            } else if CFDictionaryGetTypeID() == CFGetTypeID(actualResult) {
                let item = actualResult
                let localCertificate = item as! SecCertificate
                let isPubKeyTrusted: Bool = verifyPubKey(localCertificate, challenge)
                if isPubKeyTrusted == true {
                    return true
                }
            } else {
                print("failed to return any results from keychain")
                throw SSLPinningError.failedToRetrieveCertificateFromKeychain
            }
        }
        return false
    }
    
    /// Search teh entire keychain of certificates for our target certificate
    public func searchKeychainAndVerifyCertificate(_ certificate: SecCertificate, challenge: URLAuthenticationChallenge) -> Bool {
        let query = [kSecMatchLimit: kSecMatchLimitAll,
                     kSecReturnAttributes: true,
                     kSecReturnRef: true,
                     kSecClass: kSecClassCertificate] as CFDictionary
        var result: CFTypeRef?
        let resultCode = SecItemCopyMatching(query, &result)
        
        if resultCode == errSecSuccess {
            let actualResult = result!
            if CFArrayGetTypeID() == CFGetTypeID(actualResult) {
                // we have an array of values returned
                guard let array = (actualResult as? NSArray) as? [NSDictionary] else { return false }
                for item in array {
                    let localCertificate = item as! SecCertificate
                    let isCertificateTrusted: Bool = verifyCertificate(localCertificate, challenge)
                    if isCertificateTrusted {
                        return true
                    }
                }
                return false
            } else if CFDictionaryGetTypeID() == CFGetTypeID(actualResult) {
                // we have 1 item returned
                let item = actualResult
                let localCertificate = item as! SecCertificate
                let isCertificateTrusted: Bool = verifyCertificate(localCertificate, challenge)
                return isCertificateTrusted
            } else {
                print("failed to return any results from the keychain)
            }
        }
        return false
    }
}
