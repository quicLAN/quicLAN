/*
    Licensed under the MIT License.
*/

#include "tests.h"

int main(int argc, char** argv)
{
    bool Result = false;
    Result = TestBasicConnection();

    if (!Result) {
        return Result;
    }

    Result = TestMessageGenerateParse();

    if (!Result) {
        return Result;
    }

    Result = TestMessageParseFail();

    return Result;
}