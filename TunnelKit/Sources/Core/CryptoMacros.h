//
//  CryptoMacros.h
//  TunnelKit
//
//  Created by Davide De Rosa on 06/07/2018.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <Foundation/Foundation.h>

#define TUNNEL_CRYPTO_SUCCESS(ret) (ret > 0)
#define TUNNEL_CRYPTO_TRACK_STATUS(ret) if (ret > 0) ret =
#define TUNNEL_CRYPTO_RETURN_STATUS(ret)\
if (ret <= 0) {\
    if (error) {\
        *error = TunnelKitErrorWithCode(TunnelKitErrorCodeCryptoBoxEncryption);\
    }\
    return NO;\
}\
return YES;
