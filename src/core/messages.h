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

struct QuicLanMessage {
    std::atomic_uint32_t RefCount;
    QUIC_BUFFER QuicBuffer;
    _Field_size_bytes_(QuicBuffer.Length)
    uint8_t Buffer[0];
};

/*
    Formats a QuicLanMessageHeader into a byte buffer, with all fields fully
    populated.
    Returns a pointer to the end of the header.
*/
uint8_t*
QuicLanMessageHeaderFormat(
    _In_ QuicLanMessageType Type,
    _In_ uint16_t HostId,
    _Out_writes_bytes_(sizeof(QuicLanMessageHeader)) uint8_t* Header);


bool
QuicLanMessageHeaderParse(
    _In_reads_bytes_(sizeof(QuicLanMessageHeader)) const uint8_t* const Header,
    _Inout_ uint32_t* Offset,
    _Out_ QuicLanMessageType* Type,
    _Out_ uint16_t* HostId);

/*
    Every message includes a header, so the PayloadLength does not need to include the header length.
    Buffer is pointing to where the header starts.
*/
QuicLanMessage*
QuicLanMessageAlloc(
    _In_ uint32_t PayloadLength);

void
QuicLanMessageFree(
    _In_ QuicLanMessage* Message);
