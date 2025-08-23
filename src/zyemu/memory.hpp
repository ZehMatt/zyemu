#pragma once

#include "label.hpp"

#include <cstdint>
#include <zyemu/registers.hpp>

namespace zyemu
{

    struct Mem
    {
        std::uint16_t bitSize{};
        Reg seg{};
        Reg base{};
        Reg index{};
        std::int64_t disp{};
        std::uint8_t scale{};
        Label label{};
    };

    namespace x86
    {
        inline Mem byte_ptr(const Reg& base, std::int64_t disp = 0)
        {
            return Mem{ 8, ds, base, {}, disp, 0, {} };
        }

        inline Mem word_ptr(const Reg& base, std::int64_t disp = 0)
        {
            return Mem{ 16, ds, base, {}, disp, 0, {} };
        }

        inline Mem qword_ptr(const Reg& base, std::int64_t disp = 0)
        {
            return Mem{ 64, ds, base, {}, disp, 0, {} };
        }

        inline Mem dword_ptr(const Reg& base, std::int64_t disp = 0)
        {
            return Mem{ 32, ds, base, {}, disp, 0, {} };
        }

        inline Mem ptr(std::uint16_t bitSize, const Reg& base, std::int64_t disp = 0)
        {
            return Mem{ bitSize, ds, base, {}, disp, 0, {} };
        }

    } // namespace x86

} // namespace zyemu