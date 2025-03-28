// MacMemory - A macOS memory scanner and editor
// Created by: Adrian Maier

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <unistd.h> // For usleep()

// macOS specific includes
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <libproc.h>
#include <sys/sysctl.h>

// ANSI color codes for terminal output
namespace Color {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

// Enum for value types (using regular enum for compatibility)
enum ValueType {
    BYTE,
    INT16,
    INT32,
    INT64,
    FLOAT,
    DOUBLE,
    STRING,
    UNKNOWN
};

// String representation of value types
std::map<ValueType, std::string> valueTypeNames;

// Initialize the map in a function
void initValueTypeNames() {
    valueTypeNames[BYTE] = "Byte (1 byte)";
    valueTypeNames[INT16] = "Short (2 bytes)";
    valueTypeNames[INT32] = "Int (4 bytes)";
    valueTypeNames[INT64] = "Long (8 bytes)";
    valueTypeNames[FLOAT] = "Float (4 bytes)";
    valueTypeNames[DOUBLE] = "Double (8 bytes)";
    valueTypeNames[STRING] = "String";
    valueTypeNames[UNKNOWN] = "Unknown";
}

// Memory region structure
struct MemoryRegion {
    mach_vm_address_t start;
    mach_vm_size_t size;
    vm_prot_t protection;
    std::string name;
    bool readable;
    bool writable;
    bool executable;
};

// Memory scan result
struct ScanResult {
    mach_vm_address_t address;
    ValueType type;
    std::vector<uint8_t> value;
    std::string description;
};

// Process information
struct ProcessInfo {
    pid_t pid;
    std::string name;
};

// Main class for memory operations
class MemoryScanner {
private:
    task_t targetTask;
    pid_t targetPid;
    std::string targetName;
    std::vector<MemoryRegion> memoryRegions;
    std::vector<ScanResult> scanResults;
    std::vector<ScanResult> previousScanResults;
    bool isAttached;

public:
    MemoryScanner() : targetTask(MACH_PORT_NULL), targetPid(0), isAttached(false) {}
    
    ~MemoryScanner() {
        if (isAttached) {
            detachProcess();
        }
    }

    // List all processes
    std::vector<ProcessInfo> listProcesses() {
        std::vector<ProcessInfo> processes;
        int cntp = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        std::vector<pid_t> pids(cntp);
        
        proc_listpids(PROC_ALL_PIDS, 0, pids.data(), sizeof(pid_t) * cntp);
        
        for (int i = 0; i < cntp; i++) {
            if (pids[i] == 0) continue;
            
            char name[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_name(pids[i], name, sizeof(name)) > 0) {
                ProcessInfo info;
                info.pid = pids[i];
                info.name = name;
                processes.push_back(info);
            }
        }
        
        return processes;
    }
    
    // Attach to a process
    bool attachProcess(pid_t pid) {
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &targetTask);
        if (kr != KERN_SUCCESS) {
            std::cerr << "Failed to attach to process. Error: " << mach_error_string(kr) << std::endl;
            std::cerr << "Note: On macOS, this may require running as root or with special permissions." << std::endl;
            return false;
        }
        
        targetPid = pid;
        char name[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_name(targetPid, name, sizeof(name)) > 0) {
            targetName = name;
        } else {
            targetName = "Unknown";
        }
        
        isAttached = true;
        memoryRegions.clear();
        scanResults.clear();
        previousScanResults.clear();
        
        std::cout << "Successfully attached to process: " << targetName << " (PID: " << targetPid << ")" << std::endl;
        
        // Load memory regions
        refreshMemoryRegions();
        
        return true;
    }
    
    // Detach from process
    void detachProcess() {
        if (isAttached) {
            mach_port_deallocate(mach_task_self(), targetTask);
            targetTask = MACH_PORT_NULL;
            targetPid = 0;
            targetName = "";
            isAttached = false;
            memoryRegions.clear();
            scanResults.clear();
            previousScanResults.clear();
            std::cout << "Detached from process" << std::endl;
        }
    }
    
    // Refresh memory regions
    void refreshMemoryRegions() {
        memoryRegions.clear();
        
        mach_vm_address_t address = 0;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name;
        
        while (true) {
            kern_return_t kr = mach_vm_region(targetTask, &address, &size, 
                                             VM_REGION_BASIC_INFO_64, 
                                             (vm_region_info_t)&info, 
                                             &count, &object_name);
            
            if (kr != KERN_SUCCESS) {
                break;
            }
            
            MemoryRegion region;
            region.start = address;
            region.size = size;
            region.protection = info.protection;
            region.readable = (info.protection & VM_PROT_READ) != 0;
            region.writable = (info.protection & VM_PROT_WRITE) != 0;
            region.executable = (info.protection & VM_PROT_EXECUTE) != 0;
            
            // Get region name/type
            if (info.reserved) {
                region.name = "Reserved";
            } else if (info.protection == 0) {
                region.name = "No access";
            } else {
                std::stringstream ss;
                ss << (region.readable ? "R" : "-")
                   << (region.writable ? "W" : "-")
                   << (region.executable ? "X" : "-");
                region.name = ss.str();
            }
            
            memoryRegions.push_back(region);
            address += size;
        }
        
        std::cout << "Found " << memoryRegions.size() << " memory regions" << std::endl;
    }
    
    // Read memory
    template <typename T>
    bool readMemory(mach_vm_address_t address, T& value) {
        mach_vm_size_t size = sizeof(T);
        mach_vm_size_t data_size = 0;
        
        kern_return_t kr = mach_vm_read_overwrite(targetTask, address, size, 
                                                 (mach_vm_address_t)&value, &data_size);
        
        return (kr == KERN_SUCCESS && data_size == size);
    }
    
    // Read a block of memory
    bool readMemoryBlock(mach_vm_address_t address, void* buffer, size_t size) {
        mach_vm_size_t data_size = 0;
        
        kern_return_t kr = mach_vm_read_overwrite(targetTask, address, size, 
                                                 (mach_vm_address_t)buffer, &data_size);
        
        return (kr == KERN_SUCCESS && data_size == size);
    }
    
    // Write memory
    template <typename T>
    bool writeMemory(mach_vm_address_t address, const T& value) {
        kern_return_t kr = mach_vm_write(targetTask, address, (vm_offset_t)&value, sizeof(T));
        return (kr == KERN_SUCCESS);
    }
    
    // First scan - find values
    void firstScan(ValueType type, const std::string& value, const std::string& comparison) {
        scanResults.clear();
        previousScanResults.clear();
        
        std::cout << "Starting first scan, please wait..." << std::endl;
        
        size_t valueSize = 0;
        std::vector<uint8_t> targetValue;
        
        switch (type) {
            case ValueType::BYTE: {
                uint8_t val = static_cast<uint8_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT16: {
                int16_t val = static_cast<int16_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT32: {
                int32_t val = static_cast<int32_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT64: {
                int64_t val = static_cast<int64_t>(std::stoll(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::FLOAT: {
                float val = std::stof(value);
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::DOUBLE: {
                double val = std::stod(value);
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::STRING: {
                valueSize = value.length();
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), value.c_str(), valueSize);
                break;
            }
            default:
                std::cout << "Unsupported value type" << std::endl;
                return;
        }
        
        size_t totalRegions = memoryRegions.size();
        size_t regionsScanned = 0;
        size_t totalHits = 0;
        
        // Iterate through memory regions
        for (size_t i = 0; i < memoryRegions.size(); i++) {
            const MemoryRegion& region = memoryRegions[i];
            regionsScanned++;
            
            // Skip non-readable regions
            if (!region.readable) {
                continue;
            }
            
            // Progress update
            if (regionsScanned % 100 == 0) {
                float progress = static_cast<float>(regionsScanned) / static_cast<float>(totalRegions) * 100.0f;
                std::cout << "\rScanning... " << std::fixed << std::setprecision(1) << progress << "% complete" << std::flush;
            }
            
            // Allocate buffer for region data
            std::vector<uint8_t> buffer(region.size);
            if (!readMemoryBlock(region.start, buffer.data(), region.size)) {
                continue;
            }
            
            // Scan for values
            for (size_t offset = 0; offset <= buffer.size() - valueSize; offset++) {
                bool found = false;
                
                if (comparison == "exact") {
                    found = (memcmp(buffer.data() + offset, targetValue.data(), valueSize) == 0);
                } else if (comparison == "greater") {
                    // Implement comparison logic for each type
                    switch (type) {
                        case ValueType::BYTE: {
                            uint8_t val = *reinterpret_cast<uint8_t*>(buffer.data() + offset);
                            uint8_t target = *reinterpret_cast<uint8_t*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        case ValueType::INT16: {
                            int16_t val = *reinterpret_cast<int16_t*>(buffer.data() + offset);
                            int16_t target = *reinterpret_cast<int16_t*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        case ValueType::INT32: {
                            int32_t val = *reinterpret_cast<int32_t*>(buffer.data() + offset);
                            int32_t target = *reinterpret_cast<int32_t*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        case ValueType::INT64: {
                            int64_t val = *reinterpret_cast<int64_t*>(buffer.data() + offset);
                            int64_t target = *reinterpret_cast<int64_t*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        case ValueType::FLOAT: {
                            float val = *reinterpret_cast<float*>(buffer.data() + offset);
                            float target = *reinterpret_cast<float*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        case ValueType::DOUBLE: {
                            double val = *reinterpret_cast<double*>(buffer.data() + offset);
                            double target = *reinterpret_cast<double*>(targetValue.data());
                            found = val > target;
                            break;
                        }
                        default:
                            break;
                    }
                } else if (comparison == "less") {
                    // Similar logic for less than comparison
                    switch (type) {
                        case ValueType::BYTE: {
                            uint8_t val = *reinterpret_cast<uint8_t*>(buffer.data() + offset);
                            uint8_t target = *reinterpret_cast<uint8_t*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        case ValueType::INT16: {
                            int16_t val = *reinterpret_cast<int16_t*>(buffer.data() + offset);
                            int16_t target = *reinterpret_cast<int16_t*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        case ValueType::INT32: {
                            int32_t val = *reinterpret_cast<int32_t*>(buffer.data() + offset);
                            int32_t target = *reinterpret_cast<int32_t*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        case ValueType::INT64: {
                            int64_t val = *reinterpret_cast<int64_t*>(buffer.data() + offset);
                            int64_t target = *reinterpret_cast<int64_t*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        case ValueType::FLOAT: {
                            float val = *reinterpret_cast<float*>(buffer.data() + offset);
                            float target = *reinterpret_cast<float*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        case ValueType::DOUBLE: {
                            double val = *reinterpret_cast<double*>(buffer.data() + offset);
                            double target = *reinterpret_cast<double*>(targetValue.data());
                            found = val < target;
                            break;
                        }
                        default:
                            break;
                    }
                }
                
                if (found) {
                    ScanResult result;
                    result.address = region.start + offset;
                    result.type = type;
                    result.value.resize(valueSize);
                    memcpy(result.value.data(), buffer.data() + offset, valueSize);
                    
                    // Create description string
                    std::stringstream ss;
                    switch (type) {
                        case ValueType::BYTE:
                            ss << static_cast<int>(*reinterpret_cast<uint8_t*>(result.value.data()));
                            break;
                        case ValueType::INT16:
                            ss << *reinterpret_cast<int16_t*>(result.value.data());
                            break;
                        case ValueType::INT32:
                            ss << *reinterpret_cast<int32_t*>(result.value.data());
                            break;
                        case ValueType::INT64:
                            ss << *reinterpret_cast<int64_t*>(result.value.data());
                            break;
                        case ValueType::FLOAT:
                            ss << *reinterpret_cast<float*>(result.value.data());
                            break;
                        case ValueType::DOUBLE:
                            ss << *reinterpret_cast<double*>(result.value.data());
                            break;
                        case ValueType::STRING: {
                            std::string str(reinterpret_cast<char*>(result.value.data()), result.value.size());
                            ss << "\"" << str << "\"";
                            break;
                        }
                        default:
                            ss << "Unknown";
                            break;
                    }
                    result.description = ss.str();
                    
                    scanResults.push_back(result);
                    totalHits++;
                    
                    // Limit results to prevent memory exhaustion
                    if (totalHits >= 10000) {
                        std::cout << "\rToo many results (>10000), stopping scan" << std::endl;
                        break;
                    }
                }
            }
            
            if (totalHits >= 10000) {
                break;
            }
        }
        
        std::cout << "\rScan complete. Found " << scanResults.size() << " matches.                " << std::endl;
    }
    
    // Next scan - filter existing results
    void nextScan(ValueType type, const std::string& value, const std::string& comparison) {
        if (scanResults.empty()) {
            std::cout << "No previous scan results to filter" << std::endl;
            return;
        }
        
        // Store previous results
        previousScanResults = scanResults;
        scanResults.clear();
        
        std::cout << "Starting next scan, filtering " << previousScanResults.size() << " addresses..." << std::endl;
        
        // Parse search value
        std::vector<uint8_t> targetValue;
        size_t valueSize = 0;
        
        switch (type) {
            case ValueType::BYTE: {
                uint8_t val = static_cast<uint8_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT16: {
                int16_t val = static_cast<int16_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT32: {
                int32_t val = static_cast<int32_t>(std::stoi(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::INT64: {
                int64_t val = static_cast<int64_t>(std::stoll(value));
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::FLOAT: {
                float val = std::stof(value);
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::DOUBLE: {
                double val = std::stod(value);
                valueSize = sizeof(val);
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), &val, valueSize);
                break;
            }
            case ValueType::STRING: {
                valueSize = value.length();
                targetValue.resize(valueSize);
                memcpy(targetValue.data(), value.c_str(), valueSize);
                break;
            }
            default:
                std::cout << "Unsupported value type" << std::endl;
                return;
        }
        
        size_t totalAddresses = previousScanResults.size();
        size_t addressesChecked = 0;
        
        // Check each previous result
        for (size_t i = 0; i < previousScanResults.size(); i++) {
            const ScanResult& prevResult = previousScanResults[i];
            addressesChecked++;
            
            // Progress update
            if (addressesChecked % 1000 == 0) {
                float progress = static_cast<float>(addressesChecked) / static_cast<float>(totalAddresses) * 100.0f;
                std::cout << "\rFiltering... " << std::fixed << std::setprecision(1) << progress << "% complete" << std::flush;
            }
            
            // Read current value at address
            std::vector<uint8_t> currentValue(valueSize);
            if (!readMemoryBlock(prevResult.address, currentValue.data(), valueSize)) {
                continue;
            }
            
            bool found = false;
            
            if (comparison == "exact") {
                found = (memcmp(currentValue.data(), targetValue.data(), valueSize) == 0);
            } else if (comparison == "greater") {
                switch (type) {
                    case ValueType::BYTE: {
                        uint8_t val = *reinterpret_cast<uint8_t*>(currentValue.data());
                        uint8_t target = *reinterpret_cast<uint8_t*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    case ValueType::INT16: {
                        int16_t val = *reinterpret_cast<int16_t*>(currentValue.data());
                        int16_t target = *reinterpret_cast<int16_t*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    case ValueType::INT32: {
                        int32_t val = *reinterpret_cast<int32_t*>(currentValue.data());
                        int32_t target = *reinterpret_cast<int32_t*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    case ValueType::INT64: {
                        int64_t val = *reinterpret_cast<int64_t*>(currentValue.data());
                        int64_t target = *reinterpret_cast<int64_t*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    case ValueType::FLOAT: {
                        float val = *reinterpret_cast<float*>(currentValue.data());
                        float target = *reinterpret_cast<float*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    case ValueType::DOUBLE: {
                        double val = *reinterpret_cast<double*>(currentValue.data());
                        double target = *reinterpret_cast<double*>(targetValue.data());
                        found = val > target;
                        break;
                    }
                    default:
                        break;
                }
            } else if (comparison == "less") {
                switch (type) {
                    case ValueType::BYTE: {
                        uint8_t val = *reinterpret_cast<uint8_t*>(currentValue.data());
                        uint8_t target = *reinterpret_cast<uint8_t*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    case ValueType::INT16: {
                        int16_t val = *reinterpret_cast<int16_t*>(currentValue.data());
                        int16_t target = *reinterpret_cast<int16_t*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    case ValueType::INT32: {
                        int32_t val = *reinterpret_cast<int32_t*>(currentValue.data());
                        int32_t target = *reinterpret_cast<int32_t*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    case ValueType::INT64: {
                        int64_t val = *reinterpret_cast<int64_t*>(currentValue.data());
                        int64_t target = *reinterpret_cast<int64_t*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    case ValueType::FLOAT: {
                        float val = *reinterpret_cast<float*>(currentValue.data());
                        float target = *reinterpret_cast<float*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    case ValueType::DOUBLE: {
                        double val = *reinterpret_cast<double*>(currentValue.data());
                        double target = *reinterpret_cast<double*>(targetValue.data());
                        found = val < target;
                        break;
                    }
                    default:
                        break;
                }
            } else if (comparison == "changed") {
                found = (memcmp(currentValue.data(), prevResult.value.data(), valueSize) != 0);
            } else if (comparison == "unchanged") {
                found = (memcmp(currentValue.data(), prevResult.value.data(), valueSize) == 0);
            }
            
            if (found) {
                ScanResult result = prevResult;
                result.value = currentValue;
                
                // Update description
                std::stringstream ss;
                switch (type) {
                    case ValueType::BYTE:
                        ss << static_cast<int>(*reinterpret_cast<uint8_t*>(result.value.data()));
                        break;
                    case ValueType::INT16:
                        ss << *reinterpret_cast<int16_t*>(result.value.data());
                        break;
                    case ValueType::INT32:
                        ss << *reinterpret_cast<int32_t*>(result.value.data());
                        break;
                    case ValueType::INT64:
                        ss << *reinterpret_cast<int64_t*>(result.value.data());
                        break;
                    case ValueType::FLOAT:
                        ss << *reinterpret_cast<float*>(result.value.data());
                        break;
                    case ValueType::DOUBLE:
                        ss << *reinterpret_cast<double*>(result.value.data());
                        break;
                    case ValueType::STRING: {
                        std::string str(reinterpret_cast<char*>(result.value.data()), result.value.size());
                        ss << "\"" << str << "\"";
                        break;
                    }
                    default:
                        ss << "Unknown";
                        break;
                }
                result.description = ss.str();
                
                scanResults.push_back(result);
            }
        }
        
        std::cout << "\rFiltering complete. Found " << scanResults.size() << " matches.                " << std::endl;
    }
    
    // Display scan results
    void displayResults(size_t limit = 20) {
        if (scanResults.empty()) {
            std::cout << "No scan results to display" << std::endl;
            return;
        }
        
        std::cout << Color::BOLD << "Scan Results (" << scanResults.size() << " total):" << Color::RESET << std::endl;
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << Color::BOLD << std::left << std::setw(5) << "ID" 
                  << std::setw(18) << "Address" 
                  << std::setw(12) << "Type" 
                  << "Value" << Color::RESET << std::endl;
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        
        size_t count = 0;
        for (size_t i = 0; i < scanResults.size() && count < limit; i++) {
            const auto& result = scanResults[i];
            
            std::stringstream addr;
            addr << "0x" << std::hex << std::setw(16) << std::setfill('0') << result.address;
            
            std::cout << std::left << std::setw(5) << i 
                      << std::setw(18) << addr.str() 
                      << std::setw(12) << valueTypeNames[result.type] 
                      << result.description << std::endl;
            count++;
        }
        
        if (scanResults.size() > limit) {
            std::cout << "... and " << (scanResults.size() - limit) << " more results" << std::endl;
        }
        
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
    }
    
    // Modify a value at a specific address
    template <typename T>
    bool modifyValue(mach_vm_address_t address, T value) {
        return writeMemory(address, value);
    }
    
    // Create a watchpoint for an address
    void watchAddress(mach_vm_address_t address, ValueType type, size_t updateInterval = 1000) {
        if (!isAttached) {
            std::cout << "Not attached to any process" << std::endl;
            return;
        }
        
        size_t valueSize = 0;
        switch (type) {
            case ValueType::BYTE: valueSize = 1; break;
            case ValueType::INT16: valueSize = 2; break;
            case ValueType::INT32: valueSize = 4; break;
            case ValueType::INT64: valueSize = 8; break;
            case ValueType::FLOAT: valueSize = 4; break;
            case ValueType::DOUBLE: valueSize = 8; break;
            case ValueType::STRING: valueSize = 32; break; // Default string size to watch
            default: valueSize = 4; break;
        }
        
        std::vector<uint8_t> lastValue(valueSize);
        if (!readMemoryBlock(address, lastValue.data(), valueSize)) {
            std::cout << "Failed to read initial value at address 0x" 
                      << std::hex << address << std::dec << std::endl;
            return;
        }
        
        // Display initial value
        std::cout << "Watching address 0x" << std::hex << address << std::dec 
                  << " (Type: " << valueTypeNames[type] << ")" << std::endl;
        std::cout << "Initial value: ";
        printValue(lastValue.data(), type);
        std::cout << std::endl;
        
        std::cout << "Press Ctrl+C to stop watching" << std::endl;
        
        // Watch loop
        int updateCount = 0;
        try {
            while (true) {
                std::vector<uint8_t> currentValue(valueSize);
                if (!readMemoryBlock(address, currentValue.data(), valueSize)) {
                    std::cout << "Failed to read value" << std::endl;
                    break;
                }
                
                // Check if value changed
                if (memcmp(lastValue.data(), currentValue.data(), valueSize) != 0) {
                    updateCount++;
                    std::cout << "Change detected (#" << updateCount << "): ";
                    std::cout << "Old: ";
                    printValue(lastValue.data(), type);
                    std::cout << " → New: ";
                    printValue(currentValue.data(), type);
                    std::cout << std::endl;
                    
                    // Update last value
                    lastValue = currentValue;
                }
                
                // Sleep - using older sleep method for compatibility
                usleep(updateInterval * 1000);
            }
        } catch (const std::exception& e) {
            std::cout << "Error while watching: " << e.what() << std::endl;
        }
    }
    
    // Print a value based on type
    void printValue(const void* data, ValueType type) {
        switch (type) {
            case ValueType::BYTE:
                std::cout << static_cast<int>(*reinterpret_cast<const uint8_t*>(data));
                break;
            case ValueType::INT16:
                std::cout << *reinterpret_cast<const int16_t*>(data);
                break;
            case ValueType::INT32:
                std::cout << *reinterpret_cast<const int32_t*>(data);
                break;
            case ValueType::INT64:
                std::cout << *reinterpret_cast<const int64_t*>(data);
                break;
            case ValueType::FLOAT:
                std::cout << *reinterpret_cast<const float*>(data);
                break;
            case ValueType::DOUBLE:
                std::cout << *reinterpret_cast<const double*>(data);
                break;
            case ValueType::STRING: {
                std::string str(reinterpret_cast<const char*>(data));
                std::cout << "\"" << str << "\"";
                break;
            }
            default:
                std::cout << "Unknown";
                break;
        }
    }
    
    // Load scanning patterns from file
    void loadPatterns(const std::string& filename) {
        // Implementation for loading signature patterns
    }
    
    // Save scan results to file
    void saveResults(const std::string& filename) {
        if (scanResults.empty()) {
            std::cout << "No results to save" << std::endl;
            return;
        }
        
        std::ofstream file(filename);
        if (!file) {
            std::cout << "Failed to open file: " << filename << std::endl;
            return;
        }
        
        file << "# MacMemory Scan Results" << std::endl;
        file << "# Process: " << targetName << " (PID: " << targetPid << ")" << std::endl;
        file << "# Timestamp: " << std::time(nullptr) << std::endl;
        file << "# Results: " << scanResults.size() << std::endl;
        file << "# Format: ID,Address,Type,Value,Description" << std::endl;
        
        for (size_t i = 0; i < scanResults.size(); i++) {
            const auto& result = scanResults[i];
            
            file << i << ","
                 << "0x" << std::hex << result.address << std::dec << ","
                 << static_cast<int>(result.type) << ",";
            
            // Save value as hex bytes
            for (size_t j = 0; j < result.value.size(); j++) {
                file << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(result.value[j]);
            }
            
            file << "," << result.description << std::endl;
        }
        
        file.close();
        std::cout << "Saved " << scanResults.size() << " results to " << filename << std::endl;
    }
    
    // Load scan results from file
    void loadResults(const std::string& filename) {
        // Implementation for loading saved results
    }
    
    // Get current attached process info
    void getProcessInfo() {
        if (!isAttached) {
            std::cout << "Not attached to any process" << std::endl;
            return;
        }
        
        std::cout << "Process Information:" << std::endl;
        std::cout << "  Name: " << targetName << std::endl;
        std::cout << "  PID: " << targetPid << std::endl;
        std::cout << "  Memory Regions: " << memoryRegions.size() << std::endl;
        std::cout << "  Current Scan Results: " << scanResults.size() << std::endl;
        
        // Get total memory usage
        size_t totalMemory = 0;
        for (const auto& region : memoryRegions) {
            totalMemory += region.size;
        }
        
        std::cout << "  Total Memory: " << (totalMemory / (1024 * 1024)) << " MB" << std::endl;
    }
    
    // Helper methods
    bool isProcessAttached() const { return isAttached; }
    std::string getProcessName() const { return targetName; }
    pid_t getProcessId() const { return targetPid; }
    size_t getResultCount() const { return scanResults.size(); }
};

// Command-line interface class
class CLI {
private:
    MemoryScanner scanner;
    bool running;
    std::unordered_map<std::string, std::function<void(const std::vector<std::string>&)>> commands;
    
public:
    CLI() : running(false) {
        initCommands();
    }
    
    void initCommands() {
        // Core commands
        commands["help"] = [this](const std::vector<std::string>& args) { showHelp(args); };
        commands["exit"] = [this](const std::vector<std::string>& args) { running = false; };
        commands["quit"] = [this](const std::vector<std::string>& args) { running = false; };
        
        // Process commands
        commands["ps"] = [this](const std::vector<std::string>& args) { listProcesses(args); };
        commands["attach"] = [this](const std::vector<std::string>& args) { attachProcess(args); };
        commands["detach"] = [this](const std::vector<std::string>& args) { detachProcess(args); };
        commands["info"] = [this](const std::vector<std::string>& args) { processInfo(args); };
        
        // Memory commands
        commands["regions"] = [this](const std::vector<std::string>& args) { listRegions(args); };
        commands["scan"] = [this](const std::vector<std::string>& args) { scanMemory(args); };
        commands["next"] = [this](const std::vector<std::string>& args) { nextScan(args); };
        commands["results"] = [this](const std::vector<std::string>& args) { showResults(args); };
        commands["read"] = [this](const std::vector<std::string>& args) { readMemory(args); };
        commands["write"] = [this](const std::vector<std::string>& args) { writeMemory(args); };
        commands["watch"] = [this](const std::vector<std::string>& args) { watchMemory(args); };
        
        // Data management
        commands["save"] = [this](const std::vector<std::string>& args) { saveResults(args); };
        commands["load"] = [this](const std::vector<std::string>& args) { loadResults(args); };
    }
    
    void run() {
        running = true;
        
        std::cout << Color::BOLD << Color::CYAN << "MacMemory - Memory Scanner for macOS" << Color::RESET << std::endl;
        std::cout << "Type 'help' for a list of commands" << std::endl;
        std::cout << Color::BOLD << "Remember: SIP must be disabled for memory access" << Color::RESET << std::endl;
        
        while (running) {
            std::string input;
            std::vector<std::string> args;
            
            // Display prompt based on attachment status
            if (scanner.isProcessAttached()) {
                std::cout << Color::GREEN << scanner.getProcessName() << "(" << scanner.getProcessId() << ")> " << Color::RESET;
            } else {
                std::cout << Color::YELLOW << "MacMemory> " << Color::RESET;
            }
            
            std::getline(std::cin, input);
            if (input.empty()) {
                continue;
            }
            
            // Tokenize input
            std::istringstream iss(input);
            std::string token;
            while (iss >> token) {
                args.push_back(token);
            }
            
            if (!args.empty()) {
                std::string cmd = args[0];
                args.erase(args.begin()); // Remove command from args
                
                auto it = commands.find(cmd);
                if (it != commands.end()) {
                    try {
                        it->second(args);
                    } catch (const std::exception& e) {
                        std::cout << Color::RED << "Error executing command: " << e.what() << Color::RESET << std::endl;
                    }
                } else {
                    std::cout << "Unknown command: " << cmd << ". Type 'help' for a list of commands." << std::endl;
                }
            }
        }
        
        std::cout << "Exiting MacMemory. Goodbye!" << std::endl;
    }
    
    // Command implementations
    void showHelp(const std::vector<std::string>& args) {
        std::cout << Color::BOLD << "MacMemory Commands:" << Color::RESET << std::endl;
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        
        std::cout << Color::BOLD << "Process Commands:" << Color::RESET << std::endl;
        std::cout << "  ps                    - List running processes" << std::endl;
        std::cout << "  attach <pid>          - Attach to a process by ID" << std::endl;
        std::cout << "  detach                - Detach from current process" << std::endl;
        std::cout << "  info                  - Show current process information" << std::endl;
        
        std::cout << Color::BOLD << "Memory Commands:" << Color::RESET << std::endl;
        std::cout << "  regions               - List memory regions of current process" << std::endl;
        std::cout << "  scan <type> <value> [comparison] - First memory scan" << std::endl;
        std::cout << "    Types: byte, short, int, long, float, double, string" << std::endl;
        std::cout << "    Comparison: exact, greater, less (default: exact)" << std::endl;
        std::cout << "  next <type> <value> [comparison] - Filter previous results" << std::endl;
        std::cout << "    Additional comparisons: changed, unchanged" << std::endl;
        std::cout << "  results [limit]       - Show scan results (default limit: 20)" << std::endl;
        std::cout << "  read <addr> <type>    - Read value at address" << std::endl;
        std::cout << "  write <addr> <type> <value> - Write value to address" << std::endl;
        std::cout << "  watch <addr> <type> [interval] - Watch for value changes (ms)" << std::endl;
        
        std::cout << Color::BOLD << "Data Management:" << Color::RESET << std::endl;
        std::cout << "  save <filename>       - Save scan results to file" << std::endl;
        std::cout << "  load <filename>       - Load scan results from file" << std::endl;
        
        std::cout << Color::BOLD << "Misc Commands:" << Color::RESET << std::endl;
        std::cout << "  help                  - Show this help message" << std::endl;
        std::cout << "  exit, quit            - Exit MacMemory" << std::endl;
        
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << Color::BOLD << "System Requirements:" << Color::RESET << std::endl;
        std::cout << "  - Root privileges (run with sudo)" << std::endl;
        std::cout << "  - " << Color::RED << "System Integrity Protection (SIP) must be disabled" << Color::RESET << std::endl;
        std::cout << "    To disable SIP: Restart in Recovery Mode (Command+R during startup)," << std::endl;
        std::cout << "    open Terminal and run: csrutil disable" << std::endl;
        std::cout << "    Then restart your Mac normally." << std::endl;
        
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  ps                    - List all processes" << std::endl;
        std::cout << "  attach 1234           - Attach to process with PID 1234" << std::endl;
        std::cout << "  scan int 100          - Search for integer values of 100" << std::endl;
        std::cout << "  next int 200 greater  - Find values > 200 from previous results" << std::endl;
        std::cout << "  write 0x12345678 int 500 - Write value 500 to address 0x12345678" << std::endl;
        
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << "MacMemory - Contributors: Adrian Maier" << std::endl;
    }
    
    void listProcesses(const std::vector<std::string>& args) {
        std::vector<ProcessInfo> processes = scanner.listProcesses();
        
        std::cout << Color::BOLD << "Running Processes:" << Color::RESET << std::endl;
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << Color::BOLD << std::left << std::setw(10) << "PID" << "Process Name" << Color::RESET << std::endl;
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        
        for (const auto& proc : processes) {
            std::cout << std::left << std::setw(10) << proc.pid << proc.name << std::endl;
        }
        
        std::cout << "───────────────────────────────────────────────────────────────" << std::endl;
        std::cout << processes.size() << " processes found" << std::endl;
    }
    
    void attachProcess(const std::vector<std::string>& args) {
        if (args.size() < 1) {
            std::cout << "Usage: attach <pid>" << std::endl;
            return;
        }
        
        try {
            pid_t pid = std::stoi(args[0]);
            scanner.attachProcess(pid);
        } catch (const std::exception& e) {
            std::cout << "Error: Invalid PID format" << std::endl;
        }
    }
    
    void detachProcess(const std::vector<std::string>& args) {
        scanner.detachProcess();
    }
    
    void processInfo(const std::vector<std::string>& args) {
        scanner.getProcessInfo();
    }
    
    void listRegions(const std::vector<std::string>& args) {
        // Implementation to list memory regions
    }
    
    void scanMemory(const std::vector<std::string>& args) {
        if (args.size() < 2) {
            std::cout << "Usage: scan <type> <value> [comparison]" << std::endl;
            std::cout << "Types: byte, short, int, long, float, double, string" << std::endl;
            std::cout << "Comparison: exact, greater, less (default: exact)" << std::endl;
            return;
        }
        
        if (!scanner.isProcessAttached()) {
            std::cout << "Error: Not attached to any process. Use 'attach <pid>' first." << std::endl;
            return;
        }
        
        ValueType type = ValueType::UNKNOWN;
        std::string typeStr = args[0];
        std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(), ::tolower);
        
        if (typeStr == "byte") type = ValueType::BYTE;
        else if (typeStr == "short") type = ValueType::INT16;
        else if (typeStr == "int") type = ValueType::INT32;
        else if (typeStr == "long") type = ValueType::INT64;
        else if (typeStr == "float") type = ValueType::FLOAT;
        else if (typeStr == "double") type = ValueType::DOUBLE;
        else if (typeStr == "string") type = ValueType::STRING;
        
        if (type == ValueType::UNKNOWN) {
            std::cout << "Error: Unknown value type '" << typeStr << "'" << std::endl;
            return;
        }
        
        std::string value = args[1];
        std::string comparison = "exact";
        
        if (args.size() >= 3) {
            comparison = args[2];
            std::transform(comparison.begin(), comparison.end(), comparison.begin(), ::tolower);
        }
        
        if (comparison != "exact" && comparison != "greater" && comparison != "less") {
            std::cout << "Error: Unknown comparison type '" << comparison << "'" << std::endl;
            return;
        }
        
        scanner.firstScan(type, value, comparison);
    }
    
    void nextScan(const std::vector<std::string>& args) {
        if (args.size() < 2) {
            std::cout << "Usage: next <type> <value> [comparison]" << std::endl;
            std::cout << "Types: byte, short, int, long, float, double, string" << std::endl;
            std::cout << "Comparison: exact, greater, less, changed, unchanged (default: exact)" << std::endl;
            return;
        }
        
        if (!scanner.isProcessAttached()) {
            std::cout << "Error: Not attached to any process" << std::endl;
            return;
        }
        
        if (scanner.getResultCount() == 0) {
            std::cout << "Error: No previous scan results to filter" << std::endl;
            return;
        }
        
        ValueType type = ValueType::UNKNOWN;
        std::string typeStr = args[0];
        std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(), ::tolower);
        
        if (typeStr == "byte") type = ValueType::BYTE;
        else if (typeStr == "short") type = ValueType::INT16;
        else if (typeStr == "int") type = ValueType::INT32;
        else if (typeStr == "long") type = ValueType::INT64;
        else if (typeStr == "float") type = ValueType::FLOAT;
        else if (typeStr == "double") type = ValueType::DOUBLE;
        else if (typeStr == "string") type = ValueType::STRING;
        
        if (type == ValueType::UNKNOWN) {
            std::cout << "Error: Unknown value type '" << typeStr << "'" << std::endl;
            return;
        }
        
        std::string value = args[1];
        std::string comparison = "exact";
        
        if (args.size() >= 3) {
            comparison = args[2];
            std::transform(comparison.begin(), comparison.end(), comparison.begin(), ::tolower);
        }
        
        if (comparison != "exact" && comparison != "greater" && comparison != "less" && 
            comparison != "changed" && comparison != "unchanged") {
            std::cout << "Error: Unknown comparison type '" << comparison << "'" << std::endl;
            return;
        }
        
        scanner.nextScan(type, value, comparison);
    }
    
    void showResults(const std::vector<std::string>& args) {
        size_t limit = 20;
        if (args.size() >= 1) {
            try {
                limit = std::stoi(args[0]);
            } catch (const std::exception& e) {
                std::cout << "Error: Invalid limit value" << std::endl;
                return;
            }
        }
        
        scanner.displayResults(limit);
    }
    
    void readMemory(const std::vector<std::string>& args) {
        // Implementation to read memory at address
    }
    
    void writeMemory(const std::vector<std::string>& args) {
        // Implementation to write memory at address
    }
    
    void watchMemory(const std::vector<std::string>& args) {
        // Implementation to watch memory at address
    }
    
    void saveResults(const std::vector<std::string>& args) {
        if (args.size() < 1) {
            std::cout << "Usage: save <filename>" << std::endl;
            return;
        }
        
        scanner.saveResults(args[0]);
    }
    
    void loadResults(const std::vector<std::string>& args) {
        if (args.size() < 1) {
            std::cout << "Usage: load <filename>" << std::endl;
            return;
        }
        
        scanner.loadResults(args[0]);
    }
};

int main(int argc, char* argv[]) {
    // Initialize the value type names
    initValueTypeNames();
    
    // Check for root permissions
    if (geteuid() != 0) {
        std::cout << Color::YELLOW << "Warning: MacMemory requires root permissions to access process memory." << Color::RESET << std::endl;
        std::cout << "Please run with sudo for full functionality." << std::endl;
    }
    
    // Show SIP warning
    std::cout << Color::RED << "IMPORTANT: " << Color::RESET << "MacMemory requires System Integrity Protection (SIP) to be disabled" << std::endl;
    std::cout << "         for full access to process memory on macOS." << std::endl;
    std::cout << "         See README for instructions on disabling SIP." << std::endl;
    std::cout << std::endl;
    
    CLI cli;
    cli.run();
    
    return 0;
}