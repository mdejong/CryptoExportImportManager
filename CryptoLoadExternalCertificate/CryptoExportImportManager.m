//
//  CryptoExportImportManager.m
//

/*
 The MIT License (MIT)
 
 Copyright (c) 2015 Ignacio Nieto Carvajal (http://digitalleaves.com)
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#import "CryptoExportImportManager.h"

/*
 
 EC keys: http://www.opensource.apple.com/source/security_certtool/security_certtool-55103/src/dumpasn1.cfg
 
 EC param 1
 OID = 06 07 2A 86 48 CE 3D 02 01
 Comment = ANSI X9.62 public key type
 Description = ecPublicKey (1 2 840 10045 2 1)
 
 EC param 2
 OID = 06 08 2A 86 48 CE 3D 03 01 07
 Comment = ANSI X9.62 named elliptic curve
 Description = ansiX9p256r1 (1 2 840 10045 3 1 7)
 
 OID = 06 05 2B 81 04 00 22
 Comment = SECG (Certicom) named elliptic curve
 Description = secp384r1 (1 3 132 0 34)
 
 OID = 06 05 2B 81 04 00 23
 Comment = SECG (Certicom) named elliptic curve
 Description = secp521r1 (1 3 132 0 35)
 
 EC params sequence: public key + curve 256r1
 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07
 */

// SECP256R1 EC public key header (length + EC params (sequence) + bitstring
const unsigned int kCryptoExportImportManagerSecp256r1CurveLen = 256;
static unsigned char kCryptoExportImportManagerSecp256r1header[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};
const unsigned int kCryptoExportImportManagerSecp256r1headerLen = 26;

const unsigned int kCryptoExportImportManagerSecp384r1CurveLen = 384;
static unsigned char kCryptoExportImportManagerSecp384r1header[] = {0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00};
const unsigned int kCryptoExportImportManagerSecp384r1headerLen = 23;

const unsigned int kCryptoExportImportManagerSecp521r1CurveLen = 521;
static unsigned char kCryptoExportImportManagerSecp521r1header[] = {0x30, 0x81, 0x9B, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00};
const unsigned int kCryptoExportImportManagerSecp521r1headerLen = 25;

/*
 
 RSA keys: http://www.opensource.apple.com/source/security_certtool/security_certtool-55103/src/dumpasn1.cfg
 
 OID = 06 09 2A 86 48 86 F7 0D 01 01 01
 Comment = PKCS #1
 Description = rsaEncryption (1 2 840 113549 1 1 1)
 
 NULL byte: 05 00
 */

// RSA OID header
static unsigned char kCryptoExportImportManagerRSAOIDHeader[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
const unsigned int kCryptoExportImportManagerRSAOIDHeaderLength = 15;

// ASN.1 encoding parameters.
const unsigned char kCryptoExportImportManagerASNHeaderSequenceMark = 48; // 0x30
const unsigned char kCryptoExportImportManagerASNHeaderIntegerMark = 02; // 0x32
const unsigned char kCryptoExportImportManagerASNHeaderBitstringMark = 03; //0x03
const unsigned char kCryptoExportImportManagerASNHeaderNullMark = 05; //0x05
const unsigned char kCryptoExportImportManagerASNHeaderRSAEncryptionObjectMark = 06; //0x06
const unsigned char kCryptoExportImportManagerExtendedLengthMark = 128;  // 0x80
const unsigned char kCryptoExportImportManagerASNHeaderLengthForRSA = 15;

// PEM encoding constants
static unsigned char * kCryptoExportImportManagerPublicKeyInitialTag = (unsigned char*) "-----BEGIN PUBLIC KEY-----\n";
static unsigned char * kCryptoExportImportManagerPublicKeyFinalTag = (unsigned char*) "-----END PUBLIC KEY-----";
const unsigned int kCryptoExportImportManagerPublicNumberOfCharactersInALine = 64;

@implementation CryptoExportImportManager

/**
 * Extracts the public key from a X.509 certificate and returns a valid SecKeyRef that can be
 * used in any of SecKey operations (SecKeyEncrypt, SecKeyRawVerify...).
 * Receives the certificate data in DER format.
 */

- (SecKeyRef) importPublicKeyReferenceFromDERCertificate:(NSData*)certData
{
  // first we create the certificate reference
  SecCertificateRef certRef = SecCertificateCreateWithData(nil, (CFDataRef)certData);
  if (!certRef) {
    return nil;
  }
  NSLog(@"Successfully generated a valid certificate reference from the data.");
  
  // now create a SecTrust structure from the certificate where to extract the key from
  SecTrustRef secTrust;
  OSStatus secTrustStatus = SecTrustCreateWithCertificates(certRef, nil, &secTrust);
  NSLog(@"Generating a SecTrust reference from the certificate: %@", [(__bridge NSObject*)secTrust description]);
  if (secTrustStatus != errSecSuccess) {
    return nil;
  }
  
  // now evaluate the certificate.
  SecTrustResultType resultType = 0;
  OSStatus evaluateStatus = SecTrustEvaluate(secTrust, &resultType);
  NSLog(@"Evaluating the obtained SecTrust reference: %d", evaluateStatus);
  if (evaluateStatus != errSecSuccess) {
    return nil;
  }
  
  SecKeyRef publicKeyRef = SecTrustCopyPublicKey(secTrust);
  NSLog(@"Got public key reference: %@", [(__bridge NSObject*)publicKeyRef description]);
  return publicKeyRef;
}

/**
 * Exports a key retrieved from the keychain so it can be used outside iOS (i.e: in OpenSSL).
 * Returns a DER representation of the key.
 */

- (NSData*) exportPublicKeyToDER:(NSData*)rawPublicKeyBytes
                         keyType:(NSString*)keyType
                         keySize:(unsigned int)keySize
{
    NSString *kSecAttrKeyTypeECStr = (NSString*) kSecAttrKeyTypeEC;
    NSString *kSecAttrKeyTypeRSAStr = (NSString*) kSecAttrKeyTypeRSA;
    
    if ([keyType isEqualToString:kSecAttrKeyTypeECStr]) {
        return [self exportECPublicKeyToDER:rawPublicKeyBytes keyType:keyType keySize:keySize];
    } else if ([keyType isEqualToString:kSecAttrKeyTypeRSAStr]) {
        return [self exportRSAPublicKeyToDER:rawPublicKeyBytes keyType:keyType keySize:keySize];
    }
    // unknown key type return nil
    return nil;
}

/**
 * Exports a key retrieved from the keychain so it can be used outside iOS (i.e: in OpenSSL).
 * Returns a DER representation of the key.
 */

- (NSString*) exportPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                           keyType:(NSString*)keyType
                           keySize:(unsigned int)keySize
{
    NSString *kSecAttrKeyTypeECStr = (NSString*) kSecAttrKeyTypeEC;
    NSString *kSecAttrKeyTypeRSAStr = (NSString*) kSecAttrKeyTypeRSA;
    
    if ([keyType isEqualToString:kSecAttrKeyTypeECStr]) {
        return [self exportECPublicKeyToPEM:rawPublicKeyBytes keyType:keyType keySize:keySize];
    } else if ([keyType isEqualToString:kSecAttrKeyTypeRSAStr]) {
        return [self exportRSAPublicKeyToPEM:rawPublicKeyBytes keyType:keyType keySize:keySize];
    }
    // unknown key type return nil
    return nil;
}

/**
 * This function prepares a RSA public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. By default Apple exports RSA public
 * keys in a very raw format. If we want to use it on OpenSSL, PHP or almost anywhere outside iOS, we
 * need to remove add the full PKCS#1 ASN.1 wrapping. Returns a DER representation of the key.
 */

- (NSData*) exportRSAPublicKeyToDER:(NSData*)rawPublicKeyBytes
                           keyType:(NSString*)keyType
                           keySize:(unsigned int)keySize
{
    // first we create the space for the ASN.1 header and decide about its length
    NSMutableData *headerData = [NSMutableData data];
    [headerData setLength:kCryptoExportImportManagerASNHeaderLengthForRSA];
    uint8_t *headerDataPtr = (uint8_t *) headerData.mutableBytes;
    
    int bitstringEncodingLength = [self bytesNeededForRepresentingInteger:(int)rawPublicKeyBytes.length];
    
    // start building the ASN.1 header
    headerDataPtr[0] = (uint8_t) kCryptoExportImportManagerASNHeaderSequenceMark;
    
    // total size (OID + encoding + key size) + 2 (marks)
    int totalSize = kCryptoExportImportManagerRSAOIDHeaderLength + bitstringEncodingLength + (int)rawPublicKeyBytes.length + 3;
    int totalSizebitstringEncodingLength = [self encodeASN1LengthParameter:totalSize buffer:&(headerDataPtr[1])];
    
    // bitstring header
    NSMutableData *bitstringData = [NSMutableData data];
    [bitstringData setLength:kCryptoExportImportManagerASNHeaderLengthForRSA];
    uint8_t *bitstringDataPtr = (uint8_t *) bitstringData.mutableBytes;
    
    unsigned int keyLengthBytesEncoded = 0;
    bitstringDataPtr[0] = kCryptoExportImportManagerASNHeaderBitstringMark; // key length mark
    keyLengthBytesEncoded = [self encodeASN1LengthParameter:(int)rawPublicKeyBytes.length+1 buffer:&(bitstringDataPtr[1])];
    bitstringDataPtr[keyLengthBytesEncoded + 1] = 0x00;
    
    // build DER key.
    
    NSMutableData *derKeyData = [NSMutableData dataWithCapacity:totalSize+totalSizebitstringEncodingLength];
    [derKeyData appendBytes:headerDataPtr length:totalSizebitstringEncodingLength+1];
    [derKeyData appendBytes:kCryptoExportImportManagerRSAOIDHeader length:kCryptoExportImportManagerRSAOIDHeaderLength]; // Add OID header
    [derKeyData appendBytes:bitstringDataPtr length:keyLengthBytesEncoded + 2]; // 0x03 + key bitstring length + 0x00
    [derKeyData appendData:rawPublicKeyBytes]; // public key raw data.
    
    return [NSData dataWithData:derKeyData];
}

/**
 * This function prepares a RSA public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. By default Apple exports RSA public
 * keys in a very raw format. If we want to use it on OpenSSL, PHP or almost anywhere outside iOS, we
 * need to remove add the full PKCS#1 ASN.1 wrapping. Returns a DER representation of the key.
 */

- (NSString*) exportRSAPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                            keyType:(NSString*)keyType
                            keySize:(unsigned int)keySize
{
    NSData *derData = [self exportRSAPublicKeyToDER:rawPublicKeyBytes keyType:keyType keySize:keySize];
    return [self PEMKeyFromDERKey:derData];
}

/**
 * Returns the number of bytes needed to represent an integer.
 */

- (unsigned int) bytesNeededForRepresentingInteger:(int)number
{
    if (number <= 0) { return 0; }
    unsigned int i = 1;
    unsigned int unumber = number;
    while (i < 8 && unumber >= (1 << (i * 8))) {
        i += 1;
    }
    return i;
}

/**
 * Generates an ASN.1 length sequence for the given length. Modifies the buffer parameter by
 * writing the ASN.1 sequence. The memory of buffer must be initialized (i.e: from an NSData).
 * Returns the number of bytes used to write the sequence.
 */
- (int) encodeASN1LengthParameter:(int)length
                           buffer:(uint8_t*)buffer
{
    if (length < kCryptoExportImportManagerExtendedLengthMark) {
        buffer[0] = (uint8_t) length;
        // just one byte was used, no need for length starting mark (0x80)
        return 1;
    } else {
        unsigned int extraBytes = [self bytesNeededForRepresentingInteger:(int)length];
        unsigned int currentLengthValue = length;
        
        buffer[0] = kCryptoExportImportManagerExtendedLengthMark + ((uint8_t)extraBytes);
        for ( unsigned int i = 0; i < extraBytes; i++) {
            buffer[extraBytes - i] = (uint8_t) (currentLengthValue & 0xff);
            currentLengthValue = currentLengthValue >> 8;
        }
        return extraBytes + 1; // 1 byte for the starting mark (0x80 + bytes used) + bytes used to encode length.
    }
}

/**
 * This function prepares a EC public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. It basically adds the proper ASN.1
 * header and codifies the result as valid base64 string, 64 characters split.
 * Returns a DER representation of the key.
 */

- (NSData*) exportECPublicKeyToDER:(NSData*)rawPublicKeyBytes
                           keyType:(NSString*)keyType
                           keySize:(unsigned int)keySize
{
    // first retrieve the header with the OID for the proper key curve.
    unsigned char * curveOIDHeader;
    unsigned int curveOIDHeaderLen;
    switch (keySize) {
        case kCryptoExportImportManagerSecp256r1CurveLen: {
            curveOIDHeader = kCryptoExportImportManagerSecp256r1header;
            curveOIDHeaderLen = kCryptoExportImportManagerSecp256r1headerLen;
        }
        case kCryptoExportImportManagerSecp384r1CurveLen: {
            curveOIDHeader = kCryptoExportImportManagerSecp384r1header;
            curveOIDHeaderLen = kCryptoExportImportManagerSecp384r1headerLen;
        }
        case kCryptoExportImportManagerSecp521r1CurveLen: {
            curveOIDHeader = kCryptoExportImportManagerSecp521r1header;
            curveOIDHeaderLen = kCryptoExportImportManagerSecp521r1headerLen;
        }
        default: {
            curveOIDHeader = (unsigned char *) "";
            curveOIDHeaderLen = 0;
        }
    }
    NSData *headerData = [NSData dataWithBytes:curveOIDHeader length:curveOIDHeaderLen];
    
    NSMutableData *publicKeyData = [NSMutableData data];
    [publicKeyData appendData:headerData];
    [publicKeyData appendData:rawPublicKeyBytes];
    
    return [NSData dataWithData:publicKeyData];
}

/**
 * This function prepares a EC public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. It basically adds the proper ASN.1
 * header and codifies the result as valid base64 string, 64 characters split.
 * Returns a DER representation of the key.
 */

- (NSString*) exportECPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                             keyType:(NSString*)keyType
                             keySize:(unsigned int)keySize {
    
    NSData *derData = [self exportECPublicKeyToDER:rawPublicKeyBytes keyType:keyType keySize:keySize];
    return [self PEMKeyFromDERKey:derData];
}

/**
 * This method transforms a DER encoded key to PEM format. It gets a Base64 representation of
 * the key and then splits this base64 string in 64 character chunks. Then it wraps it in
 * BEGIN and END key tags.
 */

- (NSString*) PEMKeyFromDERKey:(NSData*)data
{
    // split in lines of 64 characters.
    NSString *base64EncodedString = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithLineFeed];
    
    NSMutableString *mStr = [NSMutableString string];
    [mStr appendFormat:@"%s", kCryptoExportImportManagerPublicKeyInitialTag];
    [mStr appendString:base64EncodedString];
    [mStr appendFormat:@"\n%s", kCryptoExportImportManagerPublicKeyFinalTag];
    
    return [NSString stringWithString:mStr];
}

@end
