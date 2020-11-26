/*
    Licensed under the MIT License.
*/
#include "precomp.h"

void
QuicLanMessageHeaderFormat(
    _In_ QuicLanMessageType Type,
    _In_ uint16_t HostId,
    _Out_writes_bytes_(sizeof(QuicLanMessageHeader)) uint8_t* Header)
{
    using namespace std::chrono;
    static std::random_device Rand;
    int64_t CurrentTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    Header[0] = (CurrentTime >> 16) & 0xff;
    Header[1] = (CurrentTime >> 8) & 0xff;
    Header[2] = (CurrentTime & 0xff);
    Header[3] = (uint8_t) Type;
    memcpy(Header + 4, &HostId, sizeof(HostId)); // HostId is already in network order
    auto Random = Rand();
    Header[6] = (uint8_t) Random;
    Header[7] = (uint8_t) (Random >> 8);
}


bool
QuicLanMessageHeaderParse(
    _In_reads_bytes_(sizeof(QuicLanMessageHeader)) const uint8_t* const Header,
    _Out_ QuicLanMessageType* Type,
    _Out_ uint16_t* HostId)
{
    using namespace std::chrono;
    auto MessageTimestamp = milliseconds((Header[0] << 16) | (Header[1] << 8) | Header[2]);
    auto CurrentTime = milliseconds(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count() & 0xffffff);

    if (CurrentTime < MessageTimestamp) {
        // Rollover occurred.
        if ((QuicLanMaxMessageTimestamp - MessageTimestamp) + CurrentTime > QuicLanMessageExpiration) {
            return false;
        }
    } else {
        if (CurrentTime - MessageTimestamp > QuicLanMessageExpiration) {
            return false;
        }
    }
    if (Header[3] >= MaxMessageType || Header[3] == InvalidMessage) {
        return false;
    }

    *Type = (QuicLanMessageType) Header[3];
    memcpy(HostId, Header + 4, sizeof(*HostId));
    return true;
}
