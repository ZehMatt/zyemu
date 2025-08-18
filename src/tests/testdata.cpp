#pragma once

#include "testdata.hpp"

#include <array>
#include <iostream>
#include <map>

namespace zyemu::tests
{
    // Static file stream cache to avoid reopening files multiple times.
    static std::map<std::string, std::ifstream> _fileStreams;

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
            if (!haystack.empty())
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
                data.push_back(static_cast<std::byte>(byte));
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

        static constexpr auto kStringToRegMap = []() {
            auto map = std::to_array<std::pair<std::string_view, ZydisRegister>>({
                { "rax", ZYDIS_REGISTER_RAX },
                { "rbx", ZYDIS_REGISTER_RBX },
                { "rcx", ZYDIS_REGISTER_RCX },
                { "rdx", ZYDIS_REGISTER_RDX },
                { "rsi", ZYDIS_REGISTER_RSI },
                { "rdi", ZYDIS_REGISTER_RDI },
                { "rbp", ZYDIS_REGISTER_RBP },
                { "rsp", ZYDIS_REGISTER_RSP },
                { "r8", ZYDIS_REGISTER_R8 },
                { "r9", ZYDIS_REGISTER_R9 },
                { "r10", ZYDIS_REGISTER_R10 },
                { "r11", ZYDIS_REGISTER_R11 },
                { "r12", ZYDIS_REGISTER_R12 },
                { "r13", ZYDIS_REGISTER_R13 },
                { "r14", ZYDIS_REGISTER_R14 },
                { "r15", ZYDIS_REGISTER_R15 },
                { "flags", ZYDIS_REGISTER_EFLAGS },
            });

            std::sort(map.begin(), map.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

            return map;
        }();

        inline ZydisRegister parseReg(std::string_view regName)
        {
            auto it = std::lower_bound(
                kStringToRegMap.begin(), kStringToRegMap.end(), regName,
                [](const auto& p, std::string_view sv) { return p.first < sv; });
            if (it != kStringToRegMap.end() && it->first == regName)
            {
                return it->second;
            }
            return ZYDIS_REGISTER_NONE;
        }

#ifdef _DEBUG
        std::string getDebugValue(const RawData& data)
        {
            std::string debugStr;
            if (data.size() == 8)
            {
                std::uint64_t value{};
                std::memcpy(&value, data.data(), sizeof(value));
                debugStr = std::format("{:X}", value);
            }
            else if (data.size() == 4)
            {
                std::uint32_t value{};
                std::memcpy(&value, data.data(), sizeof(value));
                debugStr = std::format("{:X}", value);
            }
            else
            {
                debugStr = "Invalid size";
            }
            return debugStr;
        }
#endif

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
#ifdef _DEBUG
                regData.debugData = detail::getDebugValue(regData.data);
#endif

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

        static constexpr std::string_view kInstrPrefix = "instr:";
        static constexpr std::string_view kInPrefix = "in:";
        static constexpr std::string_view kOutPrefix = "out:";
        static constexpr std::string_view kExceptionPrefix = "exception:";

    } // namespace detail

    std::optional<InstrEntry> parseSingleInstrEntry(
        const std::string& filePath, std::streampos startOffset, std::uint64_t expectedRip)
    {
        std::ifstream& fs = _fileStreams[filePath];
        if (!fs.is_open())
        {
            std::cerr << "File is not open: " << filePath << std::endl;
            return std::nullopt;
        }

        fs.seekg(startOffset);
        if (fs.fail())
        {
            return std::nullopt;
        }

        std::string line;
        if (!std::getline(fs, line))
        {
            return std::nullopt;
        }

        if (line.empty() || !line.starts_with("instr:"))
        {
            return std::nullopt; // Mismatch
        }

        const auto lineView = std::string_view(line);
        const auto instrSegments = detail::split(lineView.substr(6), ";");
        if (instrSegments.size() != 4)
        {
            return std::nullopt;
        }

        const auto rip = detail::decodeHexValue(instrSegments[0]);
        if (!rip || rip.value() != expectedRip)
        {
            return std::nullopt; // Mismatch on RIP (safety check)
        }

        const auto instrBytes = detail::decodeHexData(instrSegments[1]);
        if (!instrBytes)
        {
            return std::nullopt;
        }

        const auto instrText = std::string(instrSegments[2]);

        const auto testEntryCount = detail::decodeNumber(instrSegments[3]);
        if (!testEntryCount)
        {
            return std::nullopt;
        }

        InstrEntry entry{};
        entry.rip = rip.value();
        entry.instrText = instrText;
        entry.instrBytes.length = static_cast<uint8_t>(instrBytes.value().size());
        std::memcpy(entry.instrBytes.bytes, instrBytes.value().data(), entry.instrBytes.length);

        for (std::uint32_t i = 0; i < testEntryCount.value(); ++i)
        {
            if (!std::getline(fs, line))
            {
                return std::nullopt;
            }

            InstrTestData testData{};

            const auto testDataSegments = detail::split(line, "|");
            for (auto seg : testDataSegments)
            {
                seg = detail::trim(seg);

                if (seg.starts_with(detail::kInPrefix))
                {
                    auto entries = detail::parseRegData(seg.substr(detail::kInPrefix.size()));
                    if (!entries)
                    {
                        return std::nullopt;
                    }
                    testData.inputs = std::move(entries.value());
                }
                else if (seg.starts_with(detail::kOutPrefix))
                {
                    auto entries = detail::parseRegData(seg.substr(detail::kOutPrefix.size()));
                    if (!entries)
                    {
                        return std::nullopt;
                    }
                    testData.outputs = std::move(entries.value());
                }
                else if (seg.starts_with(detail::kExceptionPrefix))
                {
                    auto exceptionType = detail::parseExceptionType(seg.substr(detail::kExceptionPrefix.size()));
                    if (!exceptionType)
                    {
                        return std::nullopt;
                    }
                    testData.exceptionType = exceptionType.value();
                }
                else
                {
                    return std::nullopt;
                }
            }

            entry.testEntries.push_back(std::move(testData));
        }

        // Reset state.
        fs.clear();

        return entry;
    }

    std::vector<TestParam> collectAllTestParams(const std::vector<std::string>& filePaths)
    {
        std::vector<TestParam> params;

        // Open all files and collect test parameters
        for (const auto& filePath : filePaths)
        {
            if (_fileStreams.contains(filePath) == false)
            {
                _fileStreams[filePath].open(filePath);
                if (!_fileStreams[filePath].is_open())
                {
                    _fileStreams.erase(filePath);
                }
            }
        }

        for (const auto& filePath : filePaths)
        {
            std::ifstream& fs = _fileStreams[filePath];

            std::string line;
            while (true)
            {
                std::streampos pos = fs.tellg();
                if (pos == std::streampos(-1) || !std::getline(fs, line))
                {
                    break;
                }

                if (line.empty() || !line.starts_with("instr:"))
                {
                    continue;
                }

                const auto lineView = std::string_view(line);
                const auto instrSegments = detail::split(lineView.substr(6), ";"); // Skip "instr:"
                if (instrSegments.size() != 4)
                {
                    continue;
                }

                const auto ripOpt = detail::decodeHexValue(instrSegments[0]);
                if (!ripOpt)
                {
                    continue;
                }

                // Skip decoding instrBytes (heavy, not needed for metadata)

                const auto instrText = std::string(instrSegments[2]);

                const auto testEntryCountOpt = detail::decodeNumber(instrSegments[3]);
                if (!testEntryCountOpt)
                {
                    continue;
                }

                // Add param (lightweight)
                params.push_back({ filePath, instrText, ripOpt.value(), pos });

                // Skip the test lines without parsing
                for (std::uint32_t i = 0; i < testEntryCountOpt.value(); ++i)
                {
                    if (!std::getline(fs, line))
                    {
                        break;
                    }
                }
            }

            // Reset file stream.
            fs.clear();
        }
        return params;
    }

} // namespace zyemu::tests