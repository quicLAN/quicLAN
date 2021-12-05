/*
    Licensed under the MIT License.
*/

bool
QuicLanGenerateAuthCertificate(
    _In_ const std::string& Password,
    _Out_ std::unique_ptr<uint8_t[]>& Pkcs12,
    _Out_ uint32_t& Pkcs12Length);

bool
QuicLanVerifyCertificate(
    _In_ const std::string& Password,
    _In_ QUIC_CERTIFICATE* Cert);
