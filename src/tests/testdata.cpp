#pragma once

#include "testdata.hpp"

#include <array>
#include <charconv>
#include <iostream>
#include <map>

namespace zyemu::tests
{
    // Static file stream cache to avoid reopening files multiple times.
    static std::map<std::string, std::ifstream> _fileStreams;

    namespace detail
    {
        static constexpr std::string_view kInstrPrefix = "instr:";
        static constexpr std::string_view kInPrefix = "in:";
        static constexpr std::string_view kOutPrefix = "out:";
        static constexpr std::string_view kExceptionPrefix = "exception:";
        static constexpr std::string_view kSegmentSeparator = "|";
        static constexpr std::string_view kDataSeparator = ",";
        static constexpr std::string_view kGroupSeparator = ";";

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

        static inline std::optional<std::uint64_t> decodeHexValue(std::string_view str)
        {
            if (!str.starts_with("0x"))
                return std::nullopt;

            str.remove_prefix(2);

            std::uint64_t value{};
            auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value, 16);

            if (ec != std::errc{} || ptr != str.data() + str.size())
                return std::nullopt;

            return value;
        }

        static inline std::optional<std::uint32_t> decodeNumber(std::string_view str)
        {
            std::uint32_t value{};
            auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value, 10);

            if (ec != std::errc{} || ptr != str.data() + str.size())
                return std::nullopt;

            return value;
        }

        static inline std::optional<RawData> decodeHexData(std::string_view str)
        {
            if (!str.starts_with("#"))
                return std::nullopt;

            str.remove_prefix(1);

            if (str.size() % 2 != 0) // must be even length for full bytes
                return std::nullopt;

            RawData data;
            data.reserve(str.size() / 2);

            while (!str.empty())
            {
                std::uint32_t byte{};
                auto [ptr, ec] = std::from_chars(str.data(), str.data() + 2, byte, 16);
                if (ec != std::errc{})
                    return std::nullopt;

                data.push_back(static_cast<std::byte>(byte));
                str.remove_prefix(2);
            }

            return data;
        }

        static inline std::string_view trim(std::string_view str)
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
                // General purpose.
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
                // Simd.
                { "xmm0", ZYDIS_REGISTER_XMM0 },
                { "xmm1", ZYDIS_REGISTER_XMM1 },
                { "xmm2", ZYDIS_REGISTER_XMM2 },
                { "xmm3", ZYDIS_REGISTER_XMM3 },
                { "xmm4", ZYDIS_REGISTER_XMM4 },
                { "xmm5", ZYDIS_REGISTER_XMM5 },
                { "xmm6", ZYDIS_REGISTER_XMM6 },
                { "xmm7", ZYDIS_REGISTER_XMM7 },
                { "xmm8", ZYDIS_REGISTER_XMM8 },
                { "xmm9", ZYDIS_REGISTER_XMM9 },
                { "xmm10", ZYDIS_REGISTER_XMM10 },
                { "xmm11", ZYDIS_REGISTER_XMM11 },
                { "xmm12", ZYDIS_REGISTER_XMM12 },
                { "xmm13", ZYDIS_REGISTER_XMM13 },
                { "xmm14", ZYDIS_REGISTER_XMM14 },
                { "xmm15", ZYDIS_REGISTER_XMM15 },
                // MM
                { "mm0", ZYDIS_REGISTER_MM0 },
                { "mm1", ZYDIS_REGISTER_MM1 },
                { "mm2", ZYDIS_REGISTER_MM2 },
                { "mm3", ZYDIS_REGISTER_MM3 },
                { "mm4", ZYDIS_REGISTER_MM4 },
                { "mm5", ZYDIS_REGISTER_MM5 },
                { "mm6", ZYDIS_REGISTER_MM6 },
                { "mm7", ZYDIS_REGISTER_MM7 },
                // Special.
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

            const auto pairs = detail::split(pairsStr, kDataSeparator);
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
        line.reserve(512);

        if (!std::getline(fs, line))
        {
            return std::nullopt;
        }

        if (line.empty() || !line.starts_with(detail::kInstrPrefix))
        {
            return std::nullopt; // Mismatch
        }

        const auto lineView = std::string_view(line);
        const auto instrSegments = detail::split(lineView.substr(6), detail::kGroupSeparator);
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

            const auto testDataSegments = detail::split(line, detail::kSegmentSeparator);
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

    TestParameters collectAllTestParams(const std::vector<std::string>& filePaths)
    {
        TestParameters params;

        std::ios::sync_with_stdio(false);

        // Open all files and collect test parameters
        for (const auto& filePath : filePaths)
        {
            if (_fileStreams.contains(filePath) == false)
            {
                std::ifstream inFile;
                inFile.open(filePath);

                if (!inFile.is_open())
                {
                    std::cerr << "Failed to open file: " << filePath << std::endl;
                }

                inFile.tie(nullptr); // Disable synchronization with std::cin/std::cout

                _fileStreams.emplace(filePath, std::move(inFile));
            }
        }

        for (auto& [filePath, fs] : _fileStreams)
        {
            if (!fs.is_open())
            {
                continue;
            }

            std::string line;
            line.reserve(512);

            while (true)
            {
                std::streampos pos = fs.tellg();
                if (pos == std::streampos(-1) || !std::getline(fs, line))
                {
                    break;
                }

                if (line.empty() || !line.starts_with(detail::kInstrPrefix))
                {
                    continue;
                }

                const auto lineView = std::string_view(line);
                const auto instrSegments = detail::split(lineView.substr(6), detail::kGroupSeparator); // Skip "instr:"
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
                const auto newLine = fs.widen('\n');
                for (std::uint32_t i = 0; i < testEntryCountOpt.value(); ++i)
                {
                    fs.ignore(std::numeric_limits<std::streamsize>::max(), newLine);
                }
            }

            // Reset file stream.
            fs.clear();
        }
        return params;
    }

} // namespace zyemu::tests