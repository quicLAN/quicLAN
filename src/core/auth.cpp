/*
    Licensed under the MIT License.
*/
#include "precomp.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"
#include "openssl/x509.h"

// GetCert
// GetRootCert

bool
QuicLanGenerateAuthCertificate(
    _Out_ std::unique_ptr<uint8_t[]>& Pkcs12,
    _Out_ uint32_t& Pkcs12Length)
{
    EVP_PKEY* PrivateKey = nullptr;
    X509* SelfSignedCert = nullptr;
    X509_NAME* Name = nullptr;
    PKCS12* NewPkcs12 = nullptr;
    uint8_t* Pkcs12Buffer = nullptr;
    uint8_t* Pkcs12BufferPtr = nullptr;
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

    SelfSignedCert = X509_new();
    if (SelfSignedCert == nullptr) {
        printf("Failed to allocate X509!\n");
        goto Error;
    }

    Ret = X509_set_version(SelfSignedCert, 2);
    if (Ret != 1) {
        printf("Failed to set certificate version!\n");
        goto Error;
    }

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(SelfSignedCert), 1);
    if (Ret != 1) {
        printf("Failed to set serial number!\n");
        goto Error;
    }

    X509_gmtime_adj(X509_get_notBefore(SelfSignedCert), -300);
    X509_gmtime_adj(X509_get_notAfter(SelfSignedCert), 31536000L);

    Ret = X509_set_pubkey(SelfSignedCert, PrivateKey);
    if (Ret != 1) {
        printf("Failed to set public key on cert!\n");
        goto Error;
    }

    Name = X509_get_subject_name(SelfSignedCert);
    if (Name == nullptr) {
        printf("Failed to allocate subject name!\n");
        goto Error;
    }
    Ret = X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, (unsigned char*)"quicLAN", -1, -1, 0);
    if (Ret != 1) {
        printf("Failed to set subject name!\n");
        goto Error;
    }

    Ret = X509_set_issuer_name(SelfSignedCert, Name);
    if (Ret != 1) {
        printf("Failed to set issuer name!\n");
        goto Error;
    }

    Ret = X509_sign(SelfSignedCert, PrivateKey, nullptr);
    if (Ret == 0) {
        printf("Failed to sign certificate!\n");
        goto Error;
    }

    NewPkcs12 = PKCS12_create("", "quicLAN", PrivateKey, SelfSignedCert, nullptr, -1, -1, 0, 0, 0);
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

    if (SelfSignedCert != nullptr) {
        X509_free(SelfSignedCert);
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
    _In_ QUIC_CERTIFICATE* Cert)
{
    X509* PeerCert = (X509*)Cert;
    return true;
}
