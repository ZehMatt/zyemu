#pragma once

#include <cstdint>
#include <fstream>
#include <functional>
#include <optional>
#include <sfl/small_vector.hpp>
#include <sfl/static_vector.hpp>
#include <string>
#include <vector>
#include <zydis/zydis.h>

namespace zyemu::tests
{
    enum class ExceptionType
    {
        kNone,
        kIntDivideError,
        kIntOverflow,
    };

#ifdef _DEBUG
    using RawData = std::vector<std::byte>;
#else
    using RawData = sfl::small_vector<std::byte, 8>;
#endif

    struct InstrBytes
    {
        uint8_t length{};
        std::byte bytes[15]{};

        constexpr std::span<const std::byte> data() const
        {
            return std::span<const std::byte>(bytes, length);
        }

        constexpr std::span<std::byte> data()
        {
            return std::span<std::byte>(bytes, length);
        }
    };

    struct RegData
    {
        ZydisRegister reg{};
        RawData data;
#ifdef _DEBUG
        std::string debugData;
#endif
    };

    struct InstrTestData
    {
        sfl::small_vector<RegData, 4> inputs;
        sfl::small_vector<RegData, 4> outputs;
        ExceptionType exceptionType{};
    };

    struct InstrEntry
    {
        std::uint64_t rip;
        std::string instrText;
        InstrBytes instrBytes;
        sfl::small_vector<InstrTestData, 32> testEntries;
    };

    using InstrEntries = std::vector<InstrEntry>;

    struct TestParam
    {
        std::string filePath;
        std::string instrText;
        std::uint64_t rip;          // For unique identification and matching during lazy load
        std::streampos startOffset; // Byte offset where the "instr:" line starts
    };

    std::optional<InstrEntry> parseSingleInstrEntry(
        const std::string& filePath, std::streampos startOffset, std::uint64_t expectedRip);

    std::vector<TestParam> collectAllTestParams(const std::vector<std::string>& filePaths);

    inline std::ostream& operator<<(std::ostream& os, const InstrEntry& entry)
    {
        os << entry.instrText;
        return os;
    }

} // namespace zyemu::tests