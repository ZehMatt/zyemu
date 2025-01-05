#include <array>
#include <chrono>
#include <print>
#include <zyemu/zyemu.hpp>

static constexpr std::uint64_t kShellCodeAddress = 0x0000000140007314;
static std::uint8_t kShellCode[0x1000] = {};

static constexpr std::uint64_t kStackAddress = 0x00007FFB67A49000;
static constexpr std::uint64_t kStackBaseOffset = 0x500;
static constexpr std::uint64_t kStackBase = kStackAddress + kStackBaseOffset;
static std::uint8_t kStackSpace[0x1000] = {};

zyemu::StatusCode memReadHandler(zyemu::ThreadId tid, std::uint64_t readAddress, void* dst, std::size_t size, void* userData)
{
    if (readAddress >= kShellCodeAddress && (readAddress + size) <= (kShellCodeAddress + std::size(kShellCode)))
    {
        const auto offset = readAddress - kShellCodeAddress;
        std::memcpy(dst, kShellCode + offset, size);
        return zyemu::StatusCode::success;
    }
    else if (readAddress >= kStackAddress && (readAddress + size) <= (kStackAddress + std::size(kStackSpace)))
    {
        const auto offset = readAddress - kStackAddress;
        std::memcpy(dst, kStackSpace + offset, size);
        return zyemu::StatusCode::success;
    }

    return zyemu::StatusCode::invalidMemory;
}

zyemu::StatusCode memWriteHandler(
    zyemu::ThreadId tid, std::uint64_t writeAddress, const void* src, std::size_t size, void* userData)
{
    if (writeAddress >= kShellCodeAddress && (writeAddress + size) <= (kShellCodeAddress + std::size(kShellCode)))
    {
        const auto offset = writeAddress - kShellCodeAddress;
        std::memcpy(kShellCode + offset, src, size);
        return zyemu::StatusCode::success;
    }
    else if (writeAddress >= kStackAddress && (writeAddress + size) <= (kStackAddress + std::size(kStackSpace)))
    {
        const auto offset = writeAddress - kStackAddress;
        std::memcpy(kStackSpace + offset, src, size);
        return zyemu::StatusCode::success;
    }

    return zyemu::StatusCode::invalidMemory;
}

static void testBasicMov()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x49, 0x89, 0xC4, // mov r12, rax
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    std::uint64_t testValue{ 0x1AF20384ECAB27F };

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();

    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t r12{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_R12, r12);

    assert(r12 == testValue);
}

static void testMemoryRead()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x48, 0x8B, 0x04, 0x24, // mov rax, qword ptr ss:[rsp]
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    std::uint64_t testValue{ 0x1AF20384ECAB27F };
    std::memcpy(kStackSpace + kStackBaseOffset, &testValue, sizeof(testValue));

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();

    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t rax{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

    assert(rax == testValue);
}

static void testMemoryWrite()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x48, 0x89, 0x04, 0x24, // mov qword ptr ss:[rsp], rax
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    std::memset(kStackSpace, 0xCC, sizeof(kStackSpace));

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();

    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);

    std::uint64_t testValue{ 0x1AF20384ECAB27F };
    ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t rax{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

    assert(rax == testValue);

    std::uint64_t stackValue{};
    std::memcpy(&stackValue, kStackSpace + kStackBaseOffset, sizeof(stackValue));

    assert(stackValue == testValue);
}

static void testBranchJnz()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x0F, 0x85, 0x7E, 0xFE, 0xFF, 0xFF, // jnz 0x0000000140007198
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();

    // Test with ZF == 0.
    {
        std::uint32_t flags = 0;

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);
        ctx.setRegValue(th1, ZYDIS_REGISTER_EFLAGS, flags);

        auto status = ctx.step(th1);
        if (status != zyemu::StatusCode::success)
        {
            assert(false);
        }

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        assert(rip == 0x0000000140007198);
    }

    // Test with ZF == 1.
    {
        std::uint32_t flags = (1U << 6);

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);
        ctx.setRegValue(th1, ZYDIS_REGISTER_EFLAGS, flags);

        auto status = ctx.step(th1);
        if (status != zyemu::StatusCode::success)
        {
            assert(false);
        }

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        assert(rip == kShellCodeAddress + sizeof(kTestShellCode));
    }
}

static void testPushReg64()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x50, // push rax
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    std::uint64_t testValue{ 0x1AF20384ECAB27F };

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();
    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t rsp{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
    assert(rsp == kStackBase - 8);

    std::uint64_t stackValue{};
    memReadHandler(th1, rsp, &stackValue, sizeof(stackValue), nullptr);
    assert(stackValue == testValue);
}

static void testPopReg64()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0x58, // pop rax
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    std::uint64_t testValue{ 0x1AF20384ECAB27F };

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();
    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);

    memWriteHandler(th1, kStackBase, &testValue, sizeof(testValue), nullptr);
    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t rsp{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
    assert(rsp == kStackBase + 8);

    std::uint64_t rax{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);
    assert(rax == testValue);
}

static void testCall()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00, // call 0x0000000140007198
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();
    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
    assert(rip == kShellCodeAddress + sizeof(kTestShellCode));

    std::uint64_t rsp{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
    assert(rsp == kStackBase - 8);

    std::uint64_t stackValue{};
    memReadHandler(th1, rsp, &stackValue, sizeof(stackValue), nullptr);
    assert(stackValue == kShellCodeAddress + sizeof(kTestShellCode));
}

static void testRet()
{
    constexpr std::uint8_t kTestShellCode[] = {
        0xC3, // ret
    };

    std::memcpy(kShellCode, kTestShellCode, sizeof(kTestShellCode));

    zyemu::CPU ctx{};
    ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
    ctx.setMemReadHandler(memReadHandler, nullptr);
    ctx.setMemWriteHandler(memWriteHandler, nullptr);

    auto th1 = ctx.createThread();
    ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, kStackBase);
    ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, kShellCodeAddress);

    // Push return address.
    const std::uint64_t testRetAddr = 0x0000000150007198;
    memWriteHandler(th1, kStackBase, &testRetAddr, sizeof(testRetAddr), nullptr);

    auto status = ctx.step(th1);
    if (status != zyemu::StatusCode::success)
    {
        assert(false);
    }

    std::uint64_t rip{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
    assert(rip == testRetAddr);

    std::uint64_t rsp{};
    ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
    assert(rsp == kStackBase + 8);
}

int main()
{
    testRet();
    testCall();
    testPopReg64();
    testPushReg64();
    testMemoryRead();
    testBranchJnz();
    testBasicMov();
    testMemoryWrite();

    return 0;
}