#include <windows.h>
#include <iostream>
#include <stdint.h>

static unsigned char codeBytes[] = {
    0x48, 0xB9,                    // mov rcx, <address>
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // placeholder for variable address
    0x48, 0x83, 0x01, 0x01,        // add qword ptr [rcx], 1
    0xC3                           // ret
};

int main(void)
{
    // A variable to be incremented
    int64_t counter = 0;

    std::cout << "[DEBUG] Initial counter value: " << counter << std::endl;
    std::cout << "[DEBUG] Address of counter: " << &counter << std::endl;
    system("Pause"); // Pause to verify the counter's address in Process Hacker

    // Allocate memory for the shellcode
    LPVOID execPage = VirtualAlloc(
        NULL,
        0x1000,                     // Allocate one page
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE              // Start as RW
    );
    if (!execPage)
    {
        fprintf(stderr, "[ERROR] VirtualAlloc failed. Error: %lu\n", GetLastError());
        return 1;
    }

    std::cout << "[DEBUG] Allocated executable page at: " << execPage << std::endl;
    system("Pause"); // Pause to verify the allocated memory in Process Hacker

    // Patch the codeBytes with the address of the counter variable
    void* addrCounter = reinterpret_cast<void*>(&counter);
    memcpy(&codeBytes[2], &addrCounter, sizeof(void*));

    // Print patched instructions for debugging
    std::cout << "[DEBUG] Patched codeBytes: ";
    for (size_t i = 0; i < sizeof(codeBytes); ++i)
    {
        if (i > 0 && i % 8 == 0) std::cout << " | ";
        printf("%02X ", codeBytes[i]);
    }
    std::cout << std::endl;
    system("Pause"); // Pause to verify the patched shellcode

    // Copy the shellcode into the allocated memory
    memcpy(execPage, codeBytes, sizeof(codeBytes));

    // Change memory protections to PAGE_EXECUTE_READ
    DWORD oldProtect;
    if (!VirtualProtect(execPage, 0x1000, PAGE_EXECUTE_READ, &oldProtect))
    {
        fprintf(stderr, "[ERROR] VirtualProtect failed. Error: %lu\n", GetLastError());
        return 1;
    }

    std::cout << "[DEBUG] Memory protections changed to PAGE_EXECUTE_READ." << std::endl;
    system("Pause"); // Pause to verify memory protection changes

    // Execute the function
    void (*funcPtr)(void) = reinterpret_cast<void (*)(void)>(execPage);
    std::cout << "[DEBUG] Calling shellcode..." << std::endl;
    system("Pause"); // Pause before executing the shellcode

    try
    {
        funcPtr();  // Call the dynamically generated code
    }
    catch (...)
    {
        fprintf(stderr, "[ERROR] Exception occurred while executing shellcode.\n");
    }

    // Debug: Print the value of the variable after execution
    std::cout << "[DEBUG] Counter value after shellcode execution: " << counter << std::endl;
    system("Pause"); // Pause to verify the counter value after execution

    // Restore memory protections to PAGE_NOACCESS
    if (!VirtualProtect(execPage, 0x1000, PAGE_NOACCESS, &oldProtect))
    {
        fprintf(stderr, "[ERROR] VirtualProtect to PAGE_NOACCESS failed. Error: %lu\n", GetLastError());
        return 1;
    }

    std::cout << "[DEBUG] Memory protections restored to PAGE_NOACCESS." << std::endl;
    system("Pause"); // Pause to verify memory protection changes

    // Free the allocated memory
    if (!VirtualFree(execPage, 0, MEM_RELEASE))
    {
        fprintf(stderr, "[ERROR] VirtualFree failed. Error: %lu\n", GetLastError());
    }
    else
    {
        std::cout << "[DEBUG] Executable memory freed successfully." << std::endl;
    }

    system("Pause"); // Final pause before program exit
    return 0;
}