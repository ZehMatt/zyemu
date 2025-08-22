#pragma once

#include <cstdint>

namespace zyemu
{

    struct Imm
    {
        std::int64_t value{};

        constexpr Imm() noexcept
            : value{}
        {
        }
        constexpr Imm(std::uint32_t imm) noexcept
            : value{ static_cast<std::int32_t>(imm) }
        {
        }
        constexpr Imm(std::int32_t imm) noexcept
            : value{ imm }
        {
        }
        constexpr Imm(std::int64_t imm) noexcept
            : value{ imm }
        {
        }
        constexpr Imm(std::uint64_t imm) noexcept
            : value{ static_cast<std::int64_t>(imm) }
        {
        }
        template<typename T, typename = std::enable_if_t<std::is_enum_v<T>>>
        constexpr Imm(T imm)
            : Imm(static_cast<std::underlying_type_t<T>>(imm))
        {
        }
    };

} // namespace zyemu