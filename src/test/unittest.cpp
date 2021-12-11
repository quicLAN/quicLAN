/*
    Licensed under the MIT License.
*/

#include "tests.h"
#include <atomic>
#include "../core/messages.h"

/*
    Uses the Message header functions to generate a valid message header
    and then parses that header and ensures both succeed.
*/
TEST(Messages, TestGenerateParse)
{
    QuicLanMessageHeader GeneratedHeader;
    uint32_t Offset = 0;
    const QuicLanMessageType Type = RequestId;
    QuicLanMessageType ParsedType = InvalidMessage;
    const uint32_t Length = 0;
    const uint16_t Host = 0xAA55;
    uint16_t ParsedHost = 0;
    uint32_t ParsedLength = 0;

    QuicLanMessageHeaderFormat(Type, Host, Length, (uint8_t*)&GeneratedHeader);
    ASSERT_EQ(Type, GeneratedHeader.Type);
    ASSERT_EQ(Host, GeneratedHeader.HostId);

    ASSERT_TRUE(QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, Offset, ParsedType, ParsedHost, ParsedLength));

    ASSERT_EQ(Type, ParsedType);
    ASSERT_EQ(Host, ParsedHost);
    ASSERT_EQ(Length, ParsedLength);
}


/*
    Tests that the message header parser correctly fails invalid message headers.
*/
TEST(Messages, TestParseFail)
{
    using namespace std::chrono;
    QuicLanMessageHeader GeneratedHeader;
    uint32_t Offset = 0;
    const uint32_t Length = 0;
    const uint16_t Host = 0xAA55;
    QuicLanMessageType ParsedType;
    uint16_t ParsedHost = 0;
    uint32_t ParsedLength;

    QuicLanMessageHeaderFormat(InvalidMessage, Host, Length, (uint8_t*)&GeneratedHeader);
    ASSERT_FALSE(QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, Offset, ParsedType, ParsedHost, ParsedLength));

    QuicLanMessageHeaderFormat(MaxMessageType, Host, Length, (uint8_t*)&GeneratedHeader);
    ASSERT_FALSE(QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, Offset, ParsedType, ParsedHost, ParsedLength));

    QuicLanMessageHeaderFormat((QuicLanMessageType)((uint8_t)MaxMessageType + 1), Host, Length, (uint8_t*)&GeneratedHeader);
    ASSERT_FALSE(QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, Offset, ParsedType, ParsedHost, ParsedLength));

    QuicLanMessageHeaderFormat(RequestId, Host, Length, (uint8_t*)&GeneratedHeader);
    int64_t FiveMinutesFromNow = duration_cast<milliseconds>(system_clock::now().time_since_epoch() + QuicLanMessageExpiration).count();
    FiveMinutesFromNow &= 0xffffff;
    GeneratedHeader.Timestamp[0] = (FiveMinutesFromNow >> 16) & 0xff;
    GeneratedHeader.Timestamp[1] = (FiveMinutesFromNow >> 8) & 0xff;
    GeneratedHeader.Timestamp[2] = FiveMinutesFromNow & 0xff;
    ASSERT_FALSE(QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, Offset, ParsedType, ParsedHost, ParsedLength));
}
