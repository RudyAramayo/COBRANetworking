//
//  AppleAPIClient.swift
//  COBRANetworking
//
//  Created by ROB on 1/21/22.
//

import Foundation
import Combine

struct AppleAPIClient: Request {
    var baseURL: String
    
    public init(baseURL: String) {
        self.baseURL = baseURL
    }
    
    public func iPhoneHomePage(network:Network) -> AnyPublisher<String, Error> {
        let request = iPhoneRequest()
        if let appleAPIRequest = request.asURLRequest(baseURL) {
            return network.callHTML( appleAPIRequest,
                                     queue: .global(),
                                     retries: 0)
        }
        print("Failed, erasinig to Empty Publisher!")
        return Empty(completeImmediately: false).eraseToAnyPublisher()
    }
}



class AppleAPIExampleVC: UIViewController {
    private var cancellables = [AnyCancellable]()
    var baseUrl = "https://www.apple.com"
    let apiClient: AppleAPIClient
    let network: Network?
    
    init( baseURL: String) {
        apiClient = AppleAPIClient( baseURL: baseURL)
        super.init()
        initializeNetworkLibrary(baseURL: baseURL)
        fetchiPhoneHomePage()
    }
    
    required init?(coder:NSCoder) {
        apiClient = AppleAPIClient( baseURL: baseURL)
        super.init(coder: coder)
    }
    
    func initializeNetworkLibrary(baseURL: String) {
        let pinnedCertificatesVerifier = PinnedCertificatesVerifier()
        
        let cert_url = NSURL(fileURLWithPath: Bundle.main.path(forResource: "apple", ofType: "cer")!) as URL
        guard let certData = try? Data(contentsOf: cert_url),
            let localCertificate = SecCertificateCreateWithData(nil, certData as CFData) else { return }
        try? pinnedCertificatesVerifier.registerCertificate(localCertificate, attrLabel: "www.apple.com")
        
        let sslVerifiers: [String: SSLVerifying] = ["www.apple.com": pinnedCertificatesVerifier as SSLVerifying]
        network = Network()
        network?.sslVerifiers = sslVerifiers
    }
    
    func fetchiPhoneHomePage() {
        guard let network = network else {
            apiClient.iPhoneHomePage(network: network)
                .subscribe(on:.global())
                .recieve(on:.main)
                .sink(receiveCompletion: { result in },
                      recieveValue: { value in
                        print("homepage = \(value)")
                })
                .store(in: &cancellables)
        }
    }
}
