# MacMemory

A memory scanner and editor for macOS, similar to Cheat Engine but built specifically for Mac with a powerful command-line interface.

## Features

- Process attachment and memory scanning
- Value searches (exact match, greater/less than, changed/unchanged)
- Memory region mapping and analysis
- Memory reading, writing, and real-time watching
- Support for multiple value types (byte, short, int, long, float, double, string)
- Filter results through multiple scan iterations
- Colorized CLI output for better readability
- Save and load scan results

## ⚠️ System Requirements

- macOS 10.13 or higher
- Xcode Command Line Tools or similar C++ compiler
- **Root privileges** (sudo)
- **SIP must be disabled** (see below)

### Disabling System Integrity Protection (SIP)

MacMemory requires SIP to be disabled to access process memory on macOS:

1. Restart your Mac in Recovery Mode (hold Command+R during startup)
2. Once in Recovery Mode, open Terminal from the Utilities menu
3. Run: `csrutil disable`
4. Restart your Mac normally

**Warning**: Disabling SIP reduces system security. Consider re-enabling it (`csrutil enable` in Recovery Mode) when you're not using MacMemory.

## Installation Options

### Option 1: Pre-built Fat Binary

A pre-built universal binary (supporting both Intel and Apple Silicon Macs) is available in the `dist/macmemoryfat` directory. This is the easiest way to get started:

[Download Pre-built Binary](dist/macmemoryfat)

```bash
# Navigate to the repository
cd macmemory

# Make the binary executable if needed
chmod +x dist/macmemoryfat

# Run with sudo
sudo ./dist/macmemoryfat
```

**Note**: The pre-built binary might not work on all macOS versions and configurations. If you encounter issues, please build from source as described below.

### Option 2: Building from Source

#### Using Make

```bash
git clone https://github.com/yourusername/macmemory.git
cd macmemory
make
```

#### Building a Universal Binary

To build for both Intel and Apple Silicon Macs:

```bash
make clean
make fat
```

#### Using Xcode

1. Create a new Command Line Tool project
2. Replace the default main.cpp with MacMemory code
3. Set C++ Language Dialect to C++17
4. Add `-framework Foundation` to Other Linker Flags
5. Build the project

## Installation

```bash
sudo make install
```

This installs MacMemory to `/usr/local/bin/` so you can run it from anywhere.

## Usage

Due to macOS security model, MacMemory needs to be run with root privileges:

```bash
sudo macmemory
```

### Basic Workflow

```
MacMemory> ps                    # List processes
MacMemory> attach 1234           # Attach to process with PID 1234
Game(1234)> scan int 100         # Find all int values of 100
Game(1234)> results              # Show results
Game(1234)> next int 101         # Filter for values that are now 101
Game(1234)> write 0x12345678 int 999  # Write 999 to address
Game(1234)> detach               # Detach from process
MacMemory> exit                  # Exit program
```

## Command Reference

### Process Commands
- `ps` - List running processes
- `attach <pid>` - Attach to a process
- `detach` - Detach from current process
- `info` - Show process information

### Memory Commands
- `regions` - List memory regions
- `scan <type> <value> [comparison]` - First scan
  - Types: byte, short, int, long, float, double, string
  - Comparison: exact, greater, less
- `next <type> <value> [comparison]` - Next scan
  - Additional comparisons: changed, unchanged
- `results [limit]` - Show results
- `read <addr> <type>` - Read value
- `write <addr> <type> <value>` - Write value
- `watch <addr> <type> [interval]` - Watch for changes

### Data Management
- `save <filename>` - Save results
- `load <filename>` - Load results

## Tips for Effective Use

1. Start with broad scans and narrow down with `next` scans
2. Use the "changed" or "unchanged" filters to track variables
3. Pay attention to memory region permissions (RWX)
4. For games, look for common value types (health = int, timers = float)
5. Use `watch` to confirm you've found the right memory location

## Security Notes

MacMemory is for educational purposes, game modification, and process analysis. Only use on applications you own or have permission to modify. Usage on protected applications or those with anti-cheat mechanisms may violate terms of service.

## Limitations

- Some processes are protected by SIP even when disabled
- 32-bit apps may have different memory layouts than expected
- Sandboxed apps have additional restrictions
- Not all memory regions can be accessed even with root privileges

## License

MIT License - See LICENSE file for details.

---

*Created by Adrian Maier*