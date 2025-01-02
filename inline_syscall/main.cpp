#include "syscalls.hpp"


int main() {
    if (!Syscalls::Initialize()) {
        std::cerr << "Failed to initialize syscall subsystem\n";
        return 1;
    }

    void* baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;

    auto status = Syscalls::Call("NtAllocateVirtualMemory",
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    std::cout << std::hex << std::uppercase;
    std::cout << "NtAllocateVirtualMemory status: 0x" << status << std::endl;
    std::cout << "Allocated base address: 0x" << baseAddress << std::endl;

    if (!NT_SUCCESS(status)) {
        std::cerr << "Memory allocation failed\n";
    }

    Syscalls::Cleanup();

    std::getchar();
    return 0;
}