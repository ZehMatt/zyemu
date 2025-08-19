#include "platform.hpp"

#include <cstdint>
#include <functional>

#ifdef _MSC_VER
#    include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#    include <x86intrin.h>
#else
#    error "cpuid not supported on this compiler"
#endif

namespace zyemu::platform
{
    enum class HostCapabilities : std::uint32_t
    {
        none = 0,
        sse2 = 1 << 8,
        sse4_2 = 1 << 3,
        avx = 1 << 0,
        avx2 = 1 << 1,
        avx512 = 1 << 2,
        popcnt = 1 << 4,
        bmi1 = 1 << 5,
        bmi2 = 1 << 6,
        lzcnt = 1 << 7,
    };

    inline HostCapabilities operator|(HostCapabilities lhs, HostCapabilities rhs) noexcept
    {
        return static_cast<HostCapabilities>(static_cast<int>(lhs) | static_cast<int>(rhs));
    }

    inline HostCapabilities operator&(HostCapabilities lhs, HostCapabilities rhs) noexcept
    {
        return static_cast<HostCapabilities>(static_cast<int>(lhs) & static_cast<int>(rhs));
    }

    inline bool operator!(HostCapabilities value) noexcept
    {
        return static_cast<int>(value) == 0;
    }

    static inline void cpuid(int regs[4], int leaf, int subleaf = 0) noexcept
    {
#if defined(_MSC_VER)
        __cpuidex(regs, leaf, subleaf);
#elif defined(__GNUC__) || defined(__clang__)
        __cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
#else
#    error "cpuid not supported on this compiler"
#endif
    }

    static inline std::uint64_t xgetbv(unsigned int index) noexcept
    {
        return _xgetbv(index);
    }

    static const HostCapabilities _hostCapabilities = std::invoke([]() -> HostCapabilities {
        HostCapabilities caps = HostCapabilities::none;

        int regs[4] = {};
        cpuid(regs, 1);

        // SSE2 (EDX bit 26)
        if (regs[3] & (1 << 26))
        {
            caps = caps | HostCapabilities::sse2;
        }

        // SSE4.2 (ECX bit 20)
        if (regs[2] & (1 << 20))
        {
            caps = caps | HostCapabilities::sse4_2;
        }

        // POPCNT (ECX bit 23)
        if (regs[2] & (1 << 23))
            caps = caps | HostCapabilities::popcnt;

        // OSXSAVE (ECX bit 27) + AVX (ECX bit 28)
        bool hasOSXSAVE = (regs[2] & (1 << 27)) != 0;
        bool hasAVX = (regs[2] & (1 << 28)) != 0;
        if (hasAVX && hasOSXSAVE)
        {
            uint64_t xcr0 = xgetbv(0);
            if ((xcr0 & 0x6) == 0x6)
            { // XMM (bit 1) and YMM (bit 2) enabled
                caps = caps | HostCapabilities::avx;
            }
        }

        // Extended features (leaf 7, subleaf 0)
        cpuid(regs, 7, 0);

        // AVX2 (EBX bit 5)
        if (regs[1] & (1 << 5))
        {
            caps = caps | HostCapabilities::avx2;
        }

        // BMI1 (EBX bit 3), BMI2 (EBX bit 8)
        if (regs[1] & (1 << 3))
        {
            caps = caps | HostCapabilities::bmi1;
        }
        if (regs[1] & (1 << 8))
        {
            caps = caps | HostCapabilities::bmi2;
        }

        // AVX-512 Foundation (EBX bit 16)
        bool hasAVX512F = (regs[1] & (1 << 16)) != 0;
        if (hasAVX512F && hasOSXSAVE)
        {
            uint64_t xcr0 = xgetbv(0);
            // Need XMM (bit 1), YMM (bit 2), ZMM_Hi256 (bit 5), and Hi16_ZMM (bit 6)
            if ((xcr0 & 0xE6) == 0xE6)
            {
                caps = caps | HostCapabilities::avx512;
            }
        }

        // LZCNT (leaf 0x80000001, ECX bit 5)
        cpuid(regs, 0x80000001);
        if (regs[2] & (1 << 5))
        {
            caps = caps | HostCapabilities::lzcnt;
        }

        return caps;
    });

    static inline bool hasCapability(HostCapabilities cap) noexcept
    {
        return (_hostCapabilities & cap) != HostCapabilities::none;
    }

    bool supportsAVX() noexcept
    {
        return hasCapability(HostCapabilities::avx);
    }

    bool supportsAVX2() noexcept
    {
        return hasCapability(HostCapabilities::avx2);
    }

    bool supportsAVX512() noexcept
    {
        return hasCapability(HostCapabilities::avx512);
    }

    bool supportsSSE2() noexcept
    {
        return hasCapability(HostCapabilities::sse2);
    }

    bool supportsSSE42() noexcept
    {
        return hasCapability(HostCapabilities::sse4_2);
    }

    bool supportsPopcnt() noexcept
    {
        return hasCapability(HostCapabilities::popcnt);
    }

    bool supportsBMI1() noexcept
    {
        return hasCapability(HostCapabilities::bmi1);
    }

    bool supportsBMI2() noexcept
    {
        return hasCapability(HostCapabilities::bmi2);
    }

    bool supportsLZCNT() noexcept
    {
        return hasCapability(HostCapabilities::lzcnt);
    }

} // namespace zyemu::platform