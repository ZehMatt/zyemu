#pragma once

namespace zyemu::platform
{

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