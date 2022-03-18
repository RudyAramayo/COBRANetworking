//
//  APIError.swift
//  COBRANetworking
//
//  Created by ROB on 1/21/22.
//

import Foundation

public enum SSLPinningError: Swift.Error {
    case failedToRegisterCertificateWithKeychain
    case failedToRetrieveCertificateFromKeychain
    case failedToVerifyCertificate
    case failedToVerifyPublicKeyHash
    case failedToVerifyHostName
    
    var localizedDescription: String {
        switch self {
        case .failedToRegisterCertificateWithKeychain:
            return "Certificate Registration Failed"
        case .failedToRetrieveCertificateFromKeychain:
            return "Certificate Retrieval Failed"
        case .failedToVerifyCertificate:
            return "Failed to validate certificate"
        case .failedToVerifyPublicKeyHash:
            return "Failed to validate public key hash"
        case .failedToVerifyHostName:
            return "Failed to validate server hostName"
        }
    }
}

public enum APIError: Swift.Error {
    case requestFailed
    case invalidData
    case responseUnsuccessful
    case jsonParsingFailure
    case invalidURL
    case preventedByVerifier(_ reason: String)
    case unexpectedResponse
    case entitlementError
    case invalidToken
    
    var localizedDescription: String {
        switch self {
        case .requestFailed:
            return "Request Failed"
        case .invalidData:
            return "Invalid Data"
        case .responseUnsuccessful:
            return "Response Unsuccessful"
        case .jsonParsingFailure:
            return "JSON Parsing failure"
        case .invalidURL:
            return "Invalid URL"
        case .unexpectedResponse:
            return "Unexpected Response"
        case .entitlementError:
            return "Entitlement Error"
        case .invalidToken:
            return "Token is invalid or expired"
        }
    }
}
