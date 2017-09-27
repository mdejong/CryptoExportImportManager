//
//  CryptoExportImportManager.h

/*
The MIT License (MIT)

Copyright (c) 2015 Ignacio Nieto Carvajal (http://digitalleaves.com)
                                           
 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import <Foundation/Foundation.h>

@interface CryptoExportImportManager : NSObject

/**
 * Extracts the public key from a X.509 certificate and returns a valid SecKeyRef that can be
 * used in any of SecKey operations (SecKeyEncrypt, SecKeyRawVerify...).
 * Receives the certificate data in DER format.
 */

- (SecKeyRef) importPublicKeyReferenceFromDERCertificate:(NSData*)certData;

/**
 * Exports a key retrieved from the keychain so it can be used outside iOS (i.e: in OpenSSL).
 * Returns a DER representation of the key.
 */

- (NSData*) exportPublicKeyToDER:(NSData*)rawPublicKeyBytes
                         keyType:(NSString*)keyType
                         keySize:(unsigned int)keySize;

/**
 * Exports a key retrieved from the keychain so it can be used outside iOS (i.e: in OpenSSL).
 * Returns a DER representation of the key.
 */

- (NSString*) exportPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                           keyType:(NSString*)keyType
                           keySize:(unsigned int)keySize;

/**
 * This function prepares a RSA public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. By default Apple exports RSA public
 * keys in a very raw format. If we want to use it on OpenSSL, PHP or almost anywhere outside iOS, we
 * need to remove add the full PKCS#1 ASN.1 wrapping. Returns a DER representation of the key.
 */

- (NSData*) exportRSAPublicKeyToDER:(NSData*)rawPublicKeyBytes
                            keyType:(NSString*)keyType
                            keySize:(unsigned int)keySize;

/**
 * This function prepares a RSA public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. By default Apple exports RSA public
 * keys in a very raw format. If we want to use it on OpenSSL, PHP or almost anywhere outside iOS, we
 * need to remove add the full PKCS#1 ASN.1 wrapping. Returns a DER representation of the key.
 */

- (NSString*) exportRSAPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                              keyType:(NSString*)keyType
                              keySize:(unsigned int)keySize;

/**
 * Returns the number of bytes needed to represent an integer.
 */

- (unsigned int) bytesNeededForRepresentingInteger:(int)number;

/**
 * Generates an ASN.1 length sequence for the given length. Modifies the buffer parameter by
 * writing the ASN.1 sequence. The memory of buffer must be initialized (i.e: from an NSData).
 * Returns the number of bytes used to write the sequence.
 */
- (int) encodeASN1LengthParameter:(int)length
                           buffer:(uint8_t*)buffer;

/**
 * This function prepares a EC public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. It basically adds the proper ASN.1
 * header and codifies the result as valid base64 string, 64 characters split.
 * Returns a DER representation of the key.
 */

- (NSData*) exportECPublicKeyToDER:(NSData*)rawPublicKeyBytes
                           keyType:(NSString*)keyType
                           keySize:(unsigned int)keySize;

/**
 * This function prepares a EC public key generated with Apple SecKeyGeneratePair to be exported
 * and used outisde iOS, be it openSSL, PHP, Perl, whatever. It basically adds the proper ASN.1
 * header and codifies the result as valid base64 string, 64 characters split.
 * Returns a DER representation of the key.
 */

- (NSString*) exportECPublicKeyToPEM:(NSData*)rawPublicKeyBytes
                             keyType:(NSString*)keyType
                             keySize:(unsigned int)keySize;

/**
 * This method transforms a DER encoded key to PEM format. It gets a Base64 representation of
 * the key and then splits this base64 string in 64 character chunks. Then it wraps it in
 * BEGIN and END key tags.
 */

- (NSString*) PEMKeyFromDERKey:(NSData*)data;

@end
