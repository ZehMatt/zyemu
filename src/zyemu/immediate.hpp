#pragma once

#include <cstdint>
#include <type_traits>

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

    namespace detail
    {

        template<typename T> struct ImmT : public Imm
        {
            static_assert(std::is_integral_v<T> || std::is_enum_v<T>, "ImmT can only be used with integral or enum types");
            constexpr ImmT(T imm) noexcept
                : Imm(static_cast<std::int64_t>(imm))
            {
            }
            constexpr operator T() const noexcept
            {
                return static_cast<T>(value);
            }
        };

    } // namespace detail

    using Imm8 = detail::ImmT<std::int8_t>;
    using Imm16 = detail::ImmT<std::int16_t>;
    using Imm32 = detail::ImmT<std::int32_t>;
    using Imm64 = detail::ImmT<std::int64_t>;

} // namespace zyemu