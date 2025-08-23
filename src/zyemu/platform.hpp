#pragma once

namespace zyemu::platform
{

#ifdef _WIN32
#    ifdef _MSC_VER
#        define ZYEMU_FASTCALL __fastcall
#    else
#        define ZYEMU_FASTCALL __attribute__((fastcall))
#    endif
#else
#    define ZYEMU_FASTCALL
    static_assert(false, "Unsupported platform");
#endif

    bool supportsSSE2() noexcept;

    bool supportsSSE42() noexcept;

    bool supportsAVX() noexcept;

    bool supportsAVX2() noexcept;

    bool supportsAVX512() noexcept;

    bool supportsPopcnt() noexcept;

    bool supportsBMI1() noexcept;

    bool supportsBMI2() noexcept;

    bool supportsLZCNT() noexcept;

} // namespace zyemu::platform