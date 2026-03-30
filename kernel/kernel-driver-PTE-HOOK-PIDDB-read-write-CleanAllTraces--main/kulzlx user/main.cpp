#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <Windows.h>
#include "../kulzlx dirver/shared.h"

// ---- Hooked syscall typedef ----
typedef NTSTATUS (NTAPI* tNtQueryCompositionSurfaceStatistics)(
    HANDLE hCompositionSurface,
    PVOID pStatistics
);

// ---- Resolve the hooked syscall ----
static tNtQueryCompositionSurfaceStatistics ResolveSyscall() {
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");
    if (!hWin32u)
        hWin32u = LoadLibraryA("win32u.dll");
    if (!hWin32u)
        return nullptr;

    return (tNtQueryCompositionSurfaceStatistics)GetProcAddress(
        hWin32u, "NtQueryCompositionSurfaceStatistics");
}

// ---- Mapper: read .sys and send to driver ----
static bool MapDriver(tNtQueryCompositionSurfaceStatistics fn,
                       const char* sysPath) {
    // Open and measure .sys file
    std::ifstream file(sysPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Failed to open: " << sysPath << std::endl;
        return false;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize <= 0 || fileSize > 16 * 1024 * 1024) {
        std::cerr << "[-] Invalid file size (" << fileSize << " bytes)"
                  << std::endl;
        return false;
    }

    auto buffer = std::make_unique<char[]>((size_t)fileSize);
    if (!file.read(buffer.get(), fileSize)) {
        std::cerr << "[-] Failed to read file" << std::endl;
        return false;
    }
    file.close();

    // Quick PE validation
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.get();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid PE: bad DOS signature" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)(buffer.get() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid PE: bad NT signature" << std::endl;
        return false;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[-] Invalid PE: not AMD64" << std::endl;
        return false;
    }

    std::cout << "[+] Read " << fileSize << " bytes from " << sysPath
              << std::endl;
    std::cout << "    Image size : 0x" << std::hex
              << nt->OptionalHeader.SizeOfImage << std::dec << std::endl;
    std::cout << "    Sections   : " << nt->FileHeader.NumberOfSections
              << std::endl;
    std::cout << "    Entry RVA  : 0x" << std::hex
              << nt->OptionalHeader.AddressOfEntryPoint << std::dec
              << std::endl;

    // Build request
    IO_REQUEST_BLOCK req = {0};
    req.token   = REQUEST_TOKEN;
    req.cmdType = CMD_MAPPER;
    req.bufPtr  = (unsigned __int64)buffer.get();
    req.bufLen  = (unsigned __int64)fileSize;

    std::cout << "[*] Sending mapper request to driver..." << std::endl;
    fn(NULL, &req);

    if (req.result == 1) {
        std::cout << "[+] SUCCESS: Driver mapped and DriverEntry executed!"
                  << std::endl;
        return true;
    } else {
        std::cerr << "[-] FAILURE: Manual mapping failed. Possible reasons:"
                  << std::endl;
        std::cerr << "    - Driver not loaded / hook not active" << std::endl;
        std::cerr << "    - Import resolution failure" << std::endl;
        std::cerr << "    - DriverEntry returned error" << std::endl;
        return false;
    }
}

// ---- Mouse test (existing functionality) ----
static void TestMouseMove(tNtQueryCompositionSurfaceStatistics fn) {
    IO_REQUEST_BLOCK req = {0};
    req.token   = REQUEST_TOKEN;
    req.cmdType = CMD_MOUSE_MOVE;
    req.virtAddr = 50;  // dx
    req.bufPtr   = 50;  // dy
    req.flags    = 0;   // buttons

    std::cout << "[*] Sending mouse move request (dx:50, dy:50)..."
              << std::endl;
    fn(NULL, &req);

    if (req.result == 1) {
        std::cout << "[+] Mouse move handled by driver!" << std::endl;
    } else {
        std::cout << "[-] Mouse move failed." << std::endl;
    }

    std::cout << "[*] Rapid movement loop (10 steps)..." << std::endl;
    for (int i = 0; i < 10; i++) {
        req.virtAddr = 10;
        req.bufPtr   = 10;
        fn(NULL, &req);
        Sleep(10);
    }
    std::cout << "[+] Movement loop finished." << std::endl;
}

// ---- Pulse check (verify hook is active) ----
static void PulseCheck(tNtQueryCompositionSurfaceStatistics fn) {
    IO_REQUEST_BLOCK req = {0};
    req.token   = REQUEST_TOKEN;
    req.cmdType = CMD_PULSE;

    fn(NULL, &req);

    if (req.result == RESP_ENTRY) {
        std::cout << "[+] Hook ACTIVE (PTE redirect)" << std::endl;
    } else if (req.result == RESP_CORE) {
        std::cout << "[+] Hook ACTIVE (inline patch)" << std::endl;
    } else {
        std::cout << "[-] Hook NOT active or driver not loaded" << std::endl;
    }
}

// ---- Entry point ----
int main(int argc, char* argv[]) {
    std::cout << "=====================================" << std::endl;
    std::cout << "   KULZLX  -  User Mode Client       " << std::endl;
    std::cout << "=====================================" << std::endl;

    auto fn = ResolveSyscall();
    if (!fn) {
        std::cerr << "[-] Failed to resolve NtQueryCompositionSurfaceStatistics"
                  << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Syscall at " << (void*)fn << std::endl;

    // Command-line: kulzlx_user.exe <path_to.sys>
    if (argc > 1) {
        PulseCheck(fn);
        MapDriver(fn, argv[1]);
        system("pause");
        return 0;
    }

    // Interactive menu
    while (true) {
        std::cout << "\n----- Menu -----" << std::endl;
        std::cout << "[1] Map driver (.sys)" << std::endl;
        std::cout << "[2] Test mouse move" << std::endl;
        std::cout << "[3] Pulse check" << std::endl;
        std::cout << "[0] Exit" << std::endl;
        std::cout << "> ";

        int choice = -1;
        std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        switch (choice) {
        case 1: {
            std::cout << "[*] Enter .sys file path: ";
            std::string path;
            std::cin >> path;
            MapDriver(fn, path.c_str());
            break;
        }
        case 2:
            TestMouseMove(fn);
            break;
        case 3:
            PulseCheck(fn);
            break;
        case 0:
            return 0;
        default:
            std::cout << "[-] Invalid choice." << std::endl;
            break;
        }
    }
}
