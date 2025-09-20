Status: Completed
Story: Implement macOS Wireless Packet Capture for Aircrack-ng
Author: Qwen Code
Date: 2025-09-16
Version: 1.2

## Story

### Description
This story involves implementing the macOS wireless packet capture functionality for aircrack-ng. This includes writing the code to capture 802.11 frames using libpcap/BPF and integrating it with the existing aircrack-ng OS-dependent layer.

### Acceptance Criteria
- [x] Implement `wi_read` function for packet capture using libpcap
- [x] Implement `wi_open_osdep` function to initialize wireless interfaces
- [x] Implement `wi_fd` function to provide file descriptor for select() operations
- [x] Implement `wi_get_mac` function to retrieve MAC addresses
- [x] Implement `wi_set_channel` and `wi_get_channel` functions using CoreWLAN
- [x] Implement `wi_write` function for packet injection (with limitations)
- [x] Implement `wi_get_monitor` function to check monitor mode status
- [x] Integrate with build system for macOS-specific compilation
- [x] Test functionality with airodump-ng
- [x] Document limitations and usage instructions

## Tasks/Subtasks

### Task 1: Implement Basic Packet Capture
#### Subtasks
- [x] Write `darwin_read` function using libpcap
- [x] Handle packet data and metadata correctly
- [x] Implement proper error handling and timeout management

### Task 2: Implement Interface Initialization
#### Subtasks
- [x] Write `wi_open_osdep` function to initialize interfaces
- [x] Set up libpcap handle for packet capture
- [x] Store interface information in private data structure

### Task 3: Implement File Descriptor Access
#### Subtasks
- [x] Write `darwin_fd` function to return pcap file descriptor
- [x] Ensure compatibility with select() operations

### Task 4: Implement MAC Address Retrieval
#### Subtasks
- [x] Write `darwin_get_mac` function to retrieve interface MAC
- [x] Handle ioctl operations for MAC address retrieval

### Task 5: Implement Channel Control
#### Subtasks
- [x] Write `darwin_set_channel` function using CoreWLAN
- [x] Write `darwin_get_channel` function using CoreWLAN
- [x] Handle channel to frequency conversion

### Task 6: Implement Packet Injection
#### Subtasks
- [x] Write `darwin_write` function for packet injection
- [x] Document limitations due to macOS security restrictions
- [x] Return appropriate error codes for unsupported operations

### Task 7: Implement Monitor Mode Detection
#### Subtasks
- [x] Write `darwin_get_monitor` function using CoreWLAN
- [x] Properly report monitor mode status

### Task 8: Build System Integration
#### Subtasks
- [x] CoreWLAN detection already implemented in `configure.ac` via `AIRCRACK_NG_MAC` macro
- [x] Linking against CoreWLAN framework in `lib/osdep/Makefile.inc`
- [x] Ensure proper compilation on macOS

### Task 9: Testing and Validation
#### Subtasks
- [x] Created enhanced test program `test-darwin.c`
- [x] Verified basic packet capture functionality
- [x] Tested channel setting and getting functions
- [x] Tested monitor mode detection

### Task 10: Documentation
#### Subtasks
- [x] Created user guide in `docs/macos-readme.md`
- [x] Documented limitations and usage instructions
- [x] Updated story file to reflect completed work

## Dev Agent Record

### Agent Model Used
Qwen Code (General Purpose)

### Debug Log References
- Implementation plan in `docs/macos-implementation-plan.md`
- Initial code draft in `lib/osdep/darwin.c`
- Design document in `docs/stories/brownfield-macos-design.md`

### Completion Notes List
- Basic packet capture functionality has been implemented.
- Interface initialization is working.
- File descriptor access is implemented.
- MAC address retrieval is implemented.
- CoreWLAN-based channel control has been implemented.
- Packet injection support has been added (with limitations).
- Monitor mode detection has been implemented.
- Build system properly detects and links against CoreWLAN.
- Comprehensive testing has been performed.
- User documentation has been created.

### File List
- `docs/stories/brownfield-macos-packet-capture.md` (This file)
- `lib/osdep/darwin.c`
- `docs/macos-implementation-plan.md`
- `docs/stories/brownfield-macos-design.md`
- `test-darwin.c`
- `docs/macos-readme.md`

### Change Log
- 2025-09-16: Initial draft.
- 2025-09-16: Updated status to In Progress and marked basic implementation tasks as completed based on the work done in `darwin.c`.
- 2025-09-17: Completed CoreWLAN integration, updated test program, created user documentation, and marked story as Completed.