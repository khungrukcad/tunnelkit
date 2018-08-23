//
//  Errors.h
//  TunnelKit
//
//  Created by Davide De Rosa on 10/10/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const TunnelKitErrorDomain;

typedef NS_ENUM(NSInteger, TunnelKitErrorCode) {
    TunnelKitErrorCodeCryptoBoxRandomGenerator = 101,
    TunnelKitErrorCodeCryptoBoxHMAC,
    TunnelKitErrorCodeCryptoBoxEncryption,
    TunnelKitErrorCodeCryptoBoxAlgorithm,
    TunnelKitErrorCodeTLSBoxCA = 201,
    TunnelKitErrorCodeTLSBoxHandshake,
    TunnelKitErrorCodeTLSBoxGeneric,
    TunnelKitErrorCodeDataPathOverflow = 301,
    TunnelKitErrorCodeDataPathPeerIdMismatch
};

static inline NSError *TunnelKitErrorWithCode(TunnelKitErrorCode code) {
    return [NSError errorWithDomain:TunnelKitErrorDomain code:code userInfo:nil];
}
