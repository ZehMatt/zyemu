#pragma once

#include <Zydis/Mnemonic.h>
#include <Zydis/SharedTypes.h>
#include <cstdint>
#include <sfl/static_vector.hpp>
#include <variant>
#include <zyemu/registers.hpp>

namespace zyemu
{
    struct Imm
    {
        std::int64_t value{};

        constexpr Imm() noexcept
            : value{}
        {
        }
        Imm(const void* ptr) noexcept
            : value{ reinterpret_cast<std::int64_t>(ptr) }
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

    struct Label
    {
        std::int32_t id{ -1 };

        constexpr bool isValid() const
        {
            return id != -1;
        }
    };

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

    using Operand = std::variant<Reg, Mem, Label, Imm>;

    struct Instruction
    {
        ZydisMnemonic mnemonic{};
        sfl::static_vector<Operand, 5 /*ZYDIS_ENCODER_MAX_OPERANDS*/> operands{};
    };

} // namespace zyemu