/*
    Licensed under the MIT License.
*/
#include "precomp.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"
#include "openssl/rand.h"
#include "openssl/x509v3.h"

#ifndef ED448_KEYLEN
#define ED448_KEYLEN 57
#endif

const int PBKDFIterations = 10000;
const int SigningSaltLength = 64;

void
PrintHexBuffer(const char* const Label, const uint8_t*const Buf, uint32_t Len)
{
    printf("%s: ", Label);
    for(auto i = 0; i < Len; i++) {
        printf("%02x", (unsigned char)Buf[i]);
    }
    printf("\n");
}

EVP_PKEY*
QuicLanGenerateSigningKey(
    _In_ const std::string& Password,
    _In_ const uint8_t* const Salt,
    _In_ const uint32_t SaltLen)
{
    EVP_PKEY* SigningKey = nullptr;

    uint8_t SigningKeyBytes[ED448_KEYLEN];
    int Ret = PKCS5_PBKDF2_HMAC(Password.c_str(), Password.length(), Salt, SaltLen, PBKDFIterations, EVP_sha3_512(), sizeof(SigningKeyBytes), SigningKeyBytes);
    if (Ret != 1) {
        printf("Failed to run PBKDF2!\n");
        goto Error;
    }

    SigningKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, nullptr, SigningKeyBytes, sizeof(SigningKeyBytes));
    if (SigningKey == nullptr) {
        printf("Failed to create signing key!\n");
        ERR_print_errors_cb([](const char* str, size_t len, void* u){printf("%s", str); return 1;}, nullptr);
        goto Error;
    }

Error:
    CxPlatSecureZeroMemory(SigningKeyBytes, sizeof(SigningKeyBytes));
    return SigningKey;
}

bool
QuicLanGenerateAuthCertificate(
    _In_ const std::string& Password,
    _Out_ std::unique_ptr<uint8_t[]>& Pkcs12,
    _Out_ uint32_t& Pkcs12Length)
{
    EVP_PKEY* PrivateKey = nullptr;
    EVP_PKEY* SigningKey = nullptr;
    X509* Cert = nullptr;
    X509_NAME* Name = nullptr;
    BIGNUM* SaltBn = nullptr;
    ASN1_INTEGER* SerialNumber = nullptr;
    PKCS12* NewPkcs12 = nullptr;
    uint8_t* Pkcs12Buffer = nullptr;
    uint8_t* Pkcs12BufferPtr = nullptr;
    uint8_t Salt[SigningSaltLength];
    int Ret = 0;
    bool Result = false;

    Pkcs12 = nullptr;
    Pkcs12Length = 0;

    EVP_PKEY_CTX *KeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
    if (KeyContext == nullptr) {
        printf("Failed to allocate Key context!\n");
        goto Error;
    }

    Ret = EVP_PKEY_keygen_init(KeyContext);
    if (Ret != 1) {
        printf("Keygen init failed!\n");
        goto Error;
    }

    Ret = EVP_PKEY_keygen(KeyContext, &PrivateKey);
    if (Ret != 1) {
        printf("Keygen failed!\n");
        goto Error;
    }

    Ret = RAND_bytes(Salt, sizeof(Salt));
    if (Ret != 1) {
        printf("Failed to get random bytes!\n");
        goto Error;
    }

    Cert = X509_new();
    if (Cert == nullptr) {
        printf("Failed to allocate X509!\n");
        goto Error;
    }

    Ret = X509_set_version(Cert, 2);
    if (Ret != 1) {
        printf("Failed to set certificate version!\n");
        goto Error;
    }

    SaltBn = BN_bin2bn(Salt, sizeof(Salt), nullptr);
    if (SaltBn == nullptr) {
        printf("Failed to convert Salt to BIGNUM!\n");
        goto Error;
    }

    SerialNumber = BN_to_ASN1_INTEGER(SaltBn, nullptr);
    if (SerialNumber == nullptr) {
        printf("Failed to allocate serial number!\n");
        goto Error;
    }

    Ret = X509_set_serialNumber(Cert, SerialNumber);
    if (Ret != 1) {
        printf("Failed to set serial number!\n");
        goto Error;
    }

    X509_gmtime_adj(X509_getm_notBefore(Cert), -300);
    X509_gmtime_adj(X509_getm_notAfter(Cert), 31536000L);

    Ret = X509_set_pubkey(Cert, PrivateKey);
    if (Ret != 1) {
        printf("Failed to set public key on cert!\n");
        goto Error;
    }

    Name = X509_get_subject_name(Cert);
    if (Name == nullptr) {
        printf("Failed to allocate subject name!\n");
        goto Error;
    }
    Ret = X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, (unsigned char*)"quicLAN", -1, -1, 0);
    if (Ret != 1) {
        printf("Failed to set subject name!\n");
        goto Error;
    }

    Ret = X509_set_issuer_name(Cert, Name);
    if (Ret != 1) {
        printf("Failed to set issuer name!\n");
        goto Error;
    }

    SigningKey = QuicLanGenerateSigningKey(Password, Salt, sizeof(Salt));
    if (SigningKey == nullptr) {
        goto Error;
    }

    Ret = X509_sign(Cert, SigningKey, nullptr);
    if (Ret == 0) {
        printf("Failed to sign certificate!\n");
        ERR_print_errors_cb([](const char* str, size_t len, void* u){printf("%s\n", str); return 1;}, nullptr);
        goto Error;
    }

    NewPkcs12 = PKCS12_create("", "quicLAN", PrivateKey, Cert, nullptr, -1, -1, 0, 0, 0);
    if (NewPkcs12 == nullptr) {
        printf("Failed to create new PKCS12!\n");
        goto Error;
    }

    Ret = i2d_PKCS12(NewPkcs12, nullptr);
    if (Ret <= 0) {
        printf("Failed to get export buffer size of NewPkcs12!\n");
        goto Error;
    }

    Pkcs12Length = Ret;

    Pkcs12Buffer = new (std::nothrow) uint8_t[Pkcs12Length];
    if (Pkcs12Buffer == nullptr) {
        printf("Failed to allocate %u bytes for Pkcs12!\n", Pkcs12Length);
        goto Error;
    }

    Pkcs12BufferPtr = Pkcs12Buffer;

    Ret = i2d_PKCS12(NewPkcs12, &Pkcs12BufferPtr);
    if (Ret < 0) {
        printf("Failed to export NewPkcs12!\n");
        goto Error;
    }

    if (Ret != Pkcs12Length) {
        printf("Pkcs12 export length changed between calls!\n");
        goto Error;
    }

    Result = true;
    Pkcs12.reset(Pkcs12Buffer);
    Pkcs12Buffer = nullptr;

Error:

    if (Pkcs12Buffer != nullptr) {
        delete[] Pkcs12Buffer;
    }

    if (NewPkcs12 != nullptr) {
        PKCS12_free(NewPkcs12);
    }

    if (SigningKey != nullptr) {
        EVP_PKEY_free(SigningKey);
    }

    if (SerialNumber != nullptr) {
        ASN1_INTEGER_free(SerialNumber);
    }

    if (SaltBn != nullptr) {
        BN_free(SaltBn);
    }

    if (Cert != nullptr) {
        X509_free(Cert);
    }

    if (PrivateKey != nullptr) {
        EVP_PKEY_free(PrivateKey);
    }

    if (KeyContext != nullptr) {
        EVP_PKEY_CTX_free(KeyContext);
    }

    return Result;
}


bool
QuicLanVerifyCertificate(
    _In_ const std::string& Password,
    _In_ QUIC_CERTIFICATE* Cert)
{
    EVP_PKEY* SigningKey = nullptr;
    X509* PeerCert = (X509*)Cert;
    BIGNUM* SaltBn = nullptr;
    uint8_t Salt[SigningSaltLength];
    int Ret = 0;
    bool Result = false;

    const ASN1_INTEGER* const SerialNumber = X509_get_serialNumber(PeerCert);

    SaltBn = ASN1_INTEGER_to_BN(SerialNumber, nullptr);
    if (SaltBn == nullptr) {
        printf("Failed to convert ASN SerialNumber to BIGNUM Salt!\n");
        goto Error;
    }

    if (BN_num_bytes(SaltBn) > sizeof(Salt)) {
        printf("Serial number is not correct size! %u vs %u\n", BN_num_bytes(SaltBn), sizeof(Salt));
        goto Error;
    }

    Ret = BN_bn2binpad(SaltBn, Salt, sizeof(Salt));
    if (Ret != sizeof(Salt)) {
        printf("BIGNUM conversion to binary is wrong size! %u vs %u\n", Ret, sizeof(Salt));
        goto Error;
    }

    SigningKey = QuicLanGenerateSigningKey(Password, Salt, sizeof(Salt));
    if (SigningKey == nullptr) {
        goto Error;
    }

    Ret = X509_verify(PeerCert, SigningKey);
    if (Ret == 1) {
        Result = true;
    } else if (Ret == 0) {
        printf("Certificate failed signature verification!\n");
        goto Error;
    } else if (Ret == -1) {
        printf("Certificate signature is malformed!\n");
        ERR_print_errors_cb([](const char* str, size_t len, void* u){printf("%s\n", str); return 1;}, nullptr);
        goto Error;
    } else {
        printf("Certificate failed validation for another reason!\n");
        ERR_print_errors_cb([](const char* str, size_t len, void* u){printf("%s\n", str); return 1;}, nullptr);
        goto Error;
    }

Error:
    if (SaltBn != nullptr) {
        BN_free(SaltBn);
    }

    if (SigningKey != nullptr) {
        EVP_PKEY_free(SigningKey);
    }

    return Result;
}
