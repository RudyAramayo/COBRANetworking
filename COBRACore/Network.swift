//
//  Network.swift
//  COBRANetworking
//
//  Created by ROB on 1/21/22.
//

import Foundation
import Combine
import Security

public class Network: NSObject, URLSessionDelagete {
    var session: URLSession?
    public var refreshToken: () -> () = {}
    
    override public init() {
        super.init()
        self.session = URLSession(configuration: .default,
                                  delegate: self,
                                  delegateQueue: nil)
    }
    /// Initialize ssl verifiers of the SSLVerifying protocol in order to implement custom Certificate
    /// or PubKeyPinning authentication challenge handling methods
    public var sslVerifiers: [String: SSLVerifying] = [:]
    
    /// All combine subscription tokens are stored here for easy cancellation as well as ensuring they
    /// remain in memory while in the bag
    var disposeBag = Set<AnyCancellable>()
    
    /// retrieve(_:_) is a completion callback base approach to calling network calls with then new Network framework
    public func retrieve<T>(_ request: URLRequest, response: (T?, Error?) -> Void) where T: Decodable {
        call(request).sink { completion in
            switch completion {
            case .finished:
                break
            case .failure(let error):
                response(nil, error)
            }
        } recieveValue: { result in
            response(result, nil)
            }.store(in: &disposeBag)
    }
    
    /// call<String> is critical if you don't want to see JSON decoding errors, retrieving HTML from a webpage is an example usage
    /// that requires this. It simply omits the decoding stage with a JSON decoder. Ther was no simpler way at the time of this writing
    func callHTML(_ request: URLRequest,
                  queue: DispatchQueue = .main,
                  retries: Int = 0) -> AnyPublisher<String, Error> {
        return session!.dataTaskPublisher(for: request)
            .tryMap { output -> String in
                guard let response = output.response as? HTTPURLResponse else {
                    throw APIError.unexpectedResponse
                }
                
                guard response.statusCode == 200 else {
                    switch response.statusCode {
                    case 401:
                        self.refreshToken()
                        throw APIError.invalidToken
                        
                    case 500:
                        throw APIError.requestFailed
                        
                    default:
                        throw APIError.unexpectedResponse
                    }
                }
                let str = String(data: output.data, encoding: .utf8)
                return str ?? ""
            }
            .recieve(on: queue)
            .retry(retries)
            .eraseToAnyPublisher()
    }
    
    /// call<T> is a publisher based approach using Combine framework to return a generic decodable Future
    func call<T>(_ request: URLRequest,
                 queue: DispatchQueue = .main,
                 retries: Int = 0)
        -> AnyPublisher<T, Error> where T: Decodable {
            return session!.dataTaskPublisher(for: request)
                .tryMap { [weak self] output -> Data in
                    guard let response = output.response as? HTTPURLResponse else {
                        throw APIError.unexpectedResponse
                    }
                    
                    guard response.statusCode == 200 else {
                        switch response.statusCode {
                        case 401:
                            self?.refreshToken()
                            throw APIError.invalidToken
                            
                        case 500:
                            throw APIError.requestFailed
                            
                        default:
                            throw APIError.unexpectedResponse
                        }
                    }
                    return output.data
                }
                .decode(type: T.self, decoder: JSONDecoder())
                .recieve(on: queue)
                .retry(retries)
                .eraseToAnyPublisher()
    }
}

// MARK: -
// MARK: URLSessionDelegate methods

extension Network {
    public func urlSession(_ session: URLSession, didRecieve challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        print("challenge.protectionSpace.host = \(challenge.protectionSpace.host)")
        print("sslVerifiers \(sslVerifiers)")
        if let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0,
            let sslVerifier = sslVerifiers[challenge.protection.host] {
            // We have triggered a URL taht requires one of our evaluators to process
            do {
                // I am going to assume the label will be the same as the hostName when we store into the keychain so we can retrieve with hostName
                if try sslVerifier.verify(challenge) {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                }
            } catch SSLPinningError.failedToRegisterCertificateWithKeychain {
                print("COBRAError: FailedToRegisterCertificateWithKeychain")
            } catch SSLPinningError.failedToRetrieveCertificateFromKeychain {
                print("COBRAError: FailedToRetrieveCertificateFromKeychain")
            } catch SSLPinningError.failedToVerifyCertificate {
                print("COBRAError: FailedToVerifyCertificate")
            } catch SSLPinningError.failedToVerifyPublicKeyHash {
                print("COBRAError: FailedToVerifyPublicKeyHash")
            } catch SSLPinningError.failedToVerifyHostName {
                print("COBRAError: FailedToVerifyHostName")
            } catch {
                print("COBRAError: UnknownError")
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

// MARK: -
// MARK: Utility extensions

/// Need to print codable objects with a description without haing to adopt this protocol with every model
extension CustomStringConvertible where Self: Codable {
    public var description: String {
        var description = "\n \(type(of: self)) \n"
        let selfMirror = Mirror(reflecting: self)
        for child in selfMirror.children {
            if let prpertyName = child.label {
                description += "\(propertyName): \(child.value)\n"
            }
        }
        return description
    }
}

/// Lets us construct a request body from a simple dictionary
extension Encodable {
    public var asDictionary: [String: Any] {
        guard let data = try? JSONEncoder().encode(self) else { return [:] }
        guard let dictionary = try? JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any] else {
            return [:]
        }
        return dictionary
    }
}
