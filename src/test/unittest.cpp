/*
    Licensed under the MIT License.
*/

#include "tests.h"
#include "../core/messages.h"

bool
TestMessageGenerateParse()
{
    QuicLanMessageHeader GeneratedHeader;
    const QuicLanMessageType Type = RequestId;
    QuicLanMessageType ParsedType = InvalidMessage;
    const uint16_t Host = 0xAA55;
    uint16_t ParsedHost = 0;

    QuicLanMessageHeaderFormat(Type, Host, (uint8_t*)&GeneratedHeader);
    if (Type != GeneratedHeader.Type) {
        printf(
            "Header type doesn't match input type: %x vs %x!\n",
            Type,
            GeneratedHeader.Type);
        return false;
    }
    if (Host != GeneratedHeader.HostId) {
        printf(
            "Header HostId doesn't match input HostId: %x vs %x!\n",
            Host,
            GeneratedHeader.HostId);
        return false;
    }

    if (!QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, &ParsedType, &ParsedHost)) {
        printf("Generated header failed to parse!\n");
        return false;
    }

    if (Type != ParsedType) {
        printf(
            "Parsed type doesn't match original type: %x vs %x!\n",
            Type,
            ParsedType);
        return false;
    }
    if (Host != ParsedHost) {
        printf(
            "Parsed HostId doesn't match original HostId: %x vs %x!\n",
            Host,
            ParsedHost);
        return false;
    }
    return true;
}

bool
TestMessageParseFail()
{
    using namespace std::chrono;
    QuicLanMessageHeader GeneratedHeader;
    const uint16_t Host = 0xAA55;
    QuicLanMessageType ParsedType;
    uint16_t ParsedHost = 0;

    QuicLanMessageHeaderFormat(InvalidMessage, Host, (uint8_t*)&GeneratedHeader);
    if (QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, &ParsedType, &ParsedHost)) {
        printf(
            "Parsed failed to reject %s!\n",
            "invalidMessage type");
        return false;
    }

    QuicLanMessageHeaderFormat(MaxMessageType, Host, (uint8_t*)&GeneratedHeader);
    if (QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, &ParsedType, &ParsedHost)) {
        printf(
            "Parsed failed to reject %s!\n",
            "MaxMessage type");
        return false;
    }

    QuicLanMessageHeaderFormat((QuicLanMessageType)((uint8_t)MaxMessageType + 1), Host, (uint8_t*)&GeneratedHeader);
    if (QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, &ParsedType, &ParsedHost)) {
        printf(
            "Parsed failed to reject %s!\n",
            "MaxMessage+1 type");
        return false;
    }

    QuicLanMessageHeaderFormat(RequestId, Host, (uint8_t*)&GeneratedHeader);
    int64_t FiveMinutesFromNow = duration_cast<milliseconds>(system_clock::now().time_since_epoch() + QuicLanMessageExpiration).count();
    FiveMinutesFromNow &= 0xffffff;
    GeneratedHeader.Timestamp[0] = (FiveMinutesFromNow >> 16) & 0xff;
    GeneratedHeader.Timestamp[1] = (FiveMinutesFromNow >> 8) & 0xff;
    GeneratedHeader.Timestamp[2] = FiveMinutesFromNow & 0xff;
    if (QuicLanMessageHeaderParse((uint8_t*)&GeneratedHeader, &ParsedType, &ParsedHost)) {
        printf(
            "Parsed failed to reject %s!\n",
            "too old timestamp");
        return false;
    }
    return true;
}
