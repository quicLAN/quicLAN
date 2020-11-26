/*
    Licensed under the MIT License.
*/

const std::chrono::minutes QuicLanMessageExpiration(5);
const std::chrono::milliseconds QuicLanMaxMessageTimestamp(0xffffff);

enum QuicLanMessageType:uint8_t {
    InvalidMessage = 0,
    RequestId,
    AssignId,
    RequestPeers,
    KnownPeers,
    MaxMessageType
};

union QuicLanMessageHeader {
    struct {
        uint8_t Timestamp[3];
        QuicLanMessageType Type;
        uint16_t HostId;
        uint16_t Random;
    };
    uint64_t Id;
};

void
QuicLanMessageHeaderFormat(
    _In_ QuicLanMessageType Type,
    _In_ uint16_t HostId,
    _Out_writes_bytes_(sizeof(QuicLanMessageHeader)) uint8_t* Header);


bool
QuicLanMessageHeaderParse(
    _In_reads_bytes_(sizeof(QuicLanMessageHeader)) const uint8_t* const Header,
    _Out_ QuicLanMessageType* Type,
    _Out_ uint16_t* HostId);
