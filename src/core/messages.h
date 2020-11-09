/*
    Licensed under the MIT License.
*/

enum QuicLanMessageType {
    InvalidMessage = 0,
    RequestId,
    AssignId,
    RequestPeers,
    KnownPeers
};

union QuicLanMessageId {
    struct {
        uint16_t HostId;
        uint16_t Random;
        uint32_t Timestamp;
    };
    uint64_t Id;
};

#pragma pack(push, 1)
struct QuicLanMessageHeader {
    QuicLanMessageId Id;
    uint8_t Type;
};
#pragma pack(pop)

