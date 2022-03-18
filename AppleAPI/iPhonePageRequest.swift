//
//  iPhonePageRequest.swift
//  COBRANetworking
//
//  Created by ROB on 1/21/22.
//

import Foundation
import Combine

struct iPhonePageRequest: Request {
    typealias ReturnType = String
    var path: String = "/iPhone"
    var method: HTTPMethod = .get
    var body: [String: Any]
    var headers: [String: String]?
    
    init(headers: [String: Any], body: [String: Any]) {
        self.headers = headers as? [String: String]
        self.body = body
    }
    
    init() {
        self.init(headers:[:], body:[:])
    }
}
