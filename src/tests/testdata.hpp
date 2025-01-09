#pragma once

#include <cstdint>
#include <fstream>
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

    using RawData = sfl::small_vector<std::uint8_t, 8>;

    struct RegData
    {
        ZydisRegister reg{};
        RawData data;
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
        RawData instrBytes;
        sfl::small_vector<InstrTestData, 32> testEntries;
    };

    using InstrEntries = std::vector<InstrEntry>;

    namespace detail
    {
        inline sfl::small_vector<std::string_view, 8> split(std::string_view haystack, std::string_view delim)
        {
            sfl::small_vector<std::string_view, 8> tokens{};
            std::size_t pos{};
            while ((pos = haystack.find(delim)) != std::string::npos)
            {
                tokens.push_back(haystack.substr(0, pos));
                haystack.remove_prefix(pos + delim.size());
            }
            tokens.push_back(haystack);
            return tokens;
        }

        inline std::optional<std::uint64_t> decodeHexValue(std::string_view str)
        {
            if (str.starts_with("0x") == false)
            {
                // All hex values are prefixed with 0x.
                return std::nullopt;
            }
            str.remove_prefix(2);
            return std::stoull(std::string(str), nullptr, 16);
        }

        inline std::optional<RawData> decodeHexData(std::string_view str)
        {
            if (str.starts_with("#") == false)
            {
                // All binary data is prefixed with #.
                return std::nullopt;
            }

            RawData data{};
            str.remove_prefix(1);

            data.reserve(str.size() / 2);
            while (str.empty() == false)
            {
                const auto byteStr = str.substr(0, 2);
                str.remove_prefix(2);
                const auto byte = std::stoul(std::string(byteStr), nullptr, 16);
                data.push_back(static_cast<std::uint8_t>(byte));
            }

            return data;
        }

        inline std::optional<std::uint32_t> decodeNumber(std::string_view str)
        {
            try
            {
                return std::stoul(std::string(str), nullptr, 10);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        inline std::string_view trim(std::string_view str)
        {
            while (str.starts_with(" ") || str.starts_with("\t"))
            {
                str.remove_prefix(1);
            }
            while (str.ends_with(" ") || str.ends_with("\t"))
            {
                str.remove_suffix(1);
            }
            return str;
        }

        inline ZydisRegister parseReg(std::string_view regName)
        {
            if (regName == "rax")
                return ZYDIS_REGISTER_RAX;
            if (regName == "rbx")
                return ZYDIS_REGISTER_RBX;
            if (regName == "rcx")
                return ZYDIS_REGISTER_RCX;
            if (regName == "rdx")
                return ZYDIS_REGISTER_RDX;
            if (regName == "rsi")
                return ZYDIS_REGISTER_RSI;
            if (regName == "rdi")
                return ZYDIS_REGISTER_RDI;
            if (regName == "rbp")
                return ZYDIS_REGISTER_RBP;
            if (regName == "rsp")
                return ZYDIS_REGISTER_RSP;
            if (regName == "r8")
                return ZYDIS_REGISTER_R8;
            if (regName == "r9")
                return ZYDIS_REGISTER_R9;
            if (regName == "r10")
                return ZYDIS_REGISTER_R10;
            if (regName == "r11")
                return ZYDIS_REGISTER_R11;
            if (regName == "r12")
                return ZYDIS_REGISTER_R12;
            if (regName == "r13")
                return ZYDIS_REGISTER_R13;
            if (regName == "r14")
                return ZYDIS_REGISTER_R14;
            if (regName == "r15")
                return ZYDIS_REGISTER_R15;
            if (regName == "flags")
                return ZYDIS_REGISTER_EFLAGS;
            return ZYDIS_REGISTER_NONE;
        }

        inline std::optional<sfl::small_vector<RegData, 4>> parseRegData(std::string_view pairsStr)
        {
            sfl::small_vector<RegData, 4> entries;

            const auto pairs = detail::split(pairsStr, ",");
            for (auto& pair : pairs)
            {
                const auto regPair = detail::split(pair, ":");
                if (regPair.size() != 2)
                {
                    return std::nullopt;
                }

                const auto reg = detail::parseReg(regPair[0]);
                if (reg == ZYDIS_REGISTER_NONE)
                {
                    // Invalid line.
                    return std::nullopt;
                }

                auto data = detail::decodeHexData(regPair[1]);
                if (data.has_value() == false)
                {
                    // Invalid line.
                    return std::nullopt;
                }

                RegData regData{};
                regData.reg = reg;
                regData.data = std::move(data.value());

                entries.push_back(std::move(regData));
            }

            return entries;
        }

        inline std::optional<ExceptionType> parseExceptionType(std::string_view str)
        {
            if (str == "INT_DIVIDE_ERROR")
                return ExceptionType::kIntDivideError;
            else if (str == "INT_OVERFLOW")
                return ExceptionType::kIntOverflow;

            return std::nullopt;
        }

    } // namespace detail

    inline std::optional<InstrEntries> parseTestData(std::ifstream& fs)
    {
        static constexpr std::string_view kInstrPrefix = "instr:";
        static constexpr std::string_view kInPrefix = "in:";
        static constexpr std::string_view kOutPrefix = "out:";
        static constexpr std::string_view kExceptionPrefix = "exception;";

        InstrEntries entries{};
        std::string line{};
        while (std::getline(fs, line))
        {
            if (line.empty())
                continue;

            const auto lineView = std::string_view(line);
            if (lineView.starts_with(kInstrPrefix) == false)
            {
                // Invalid line.
                return std::nullopt;
            }

            const auto instrSegments = detail::split(lineView.substr(kInstrPrefix.size()), ";");
            if (instrSegments.size() != 4)
            {
                // Invalid line.
                return std::nullopt;
            }

            const auto rip = detail::decodeHexValue(instrSegments[0]);
            if (rip.has_value() == false)
            {
                // Invalid line.
                return std::nullopt;
            }

            const auto instrBytes = detail::decodeHexData(instrSegments[1]);
            if (instrBytes.has_value() == false)
            {
                // Invalid line.
                return std::nullopt;
            }

            const auto instrText = std::string(instrSegments[2]);

            const auto testEntryCount = detail::decodeNumber(instrSegments[3]);
            if (testEntryCount.has_value() == false)
            {
                // Invalid line.
                return std::nullopt;
            }

            InstrEntry entry{};
            entry.rip = rip.value();
            entry.instrText = instrText;
            entry.instrBytes = instrBytes.value();

            for (std::uint32_t i = 0; i < testEntryCount.value(); ++i)
            {
                std::string testLine{};
                if (!std::getline(fs, testLine))
                {
                    // Invalid line.
                    return std::nullopt;
                }

                InstrTestData testData{};

                const auto testDataSegments = detail::split(testLine, "|");
                for (auto seg : testDataSegments)
                {
                    seg = detail::trim(seg);

                    if (seg.starts_with(kInPrefix))
                    {
                        const auto inputs = seg.substr(kInPrefix.size());

                        auto entries = detail::parseRegData(inputs);
                        if (entries.has_value() == false)
                        {
                            // Invalid line.
                            return std::nullopt;
                        }

                        testData.inputs = std::move(entries.value());
                    }
                    else if (seg.starts_with(kOutPrefix))
                    {
                        const auto outputs = seg.substr(kOutPrefix.size());

                        auto entries = detail::parseRegData(outputs);
                        if (entries.has_value() == false)
                        {
                            // Invalid line.
                            return std::nullopt;
                        }

                        testData.outputs = std::move(entries.value());
                    }
                    else if (seg.starts_with(kExceptionPrefix))
                    {
                        const auto exception = seg.substr(kExceptionPrefix.size());

                        const auto exceptionType = detail::parseExceptionType(exception);
                        if (exceptionType.has_value() == false)
                        {
                            // Invalid line.
                            return std::nullopt;
                        }

                        testData.exceptionType = exceptionType.value();
                    }
                    else
                    {
                        // Invalid line.
                        return std::nullopt;
                    }
                }

                entry.testEntries.push_back(std::move(testData));
            }

            entries.push_back(std::move(entry));
        }
        return entries;
    }

    inline std::optional<InstrEntries> parseTestData(const std::string& filename)
    {
        std::ifstream fs(filename);
        if (!fs.is_open())
        {
            return std::nullopt;
        }
        return parseTestData(fs);
    }

} // namespace zyemu::tests