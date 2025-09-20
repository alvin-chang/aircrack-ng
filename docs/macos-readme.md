# Aircrack-ng on macOS

This document provides instructions for using aircrack-ng on macOS, including installation requirements, permission setup, and known limitations.

## Prerequisites

### Hardware Requirements
- A compatible wireless adapter (built-in adapters have limited capabilities)
- For full functionality, we recommend using an external USB wireless adapter that supports monitor mode

### Software Requirements
- macOS 10.12 (Sierra) or later
- Xcode Command Line Tools
- Homebrew (recommended for package management)

## Installation

### Using Homebrew (Recommended)

```bash
# Install dependencies
brew install autoconf automake libtool openssl libpcap pcre

# Clone the repository
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng

# Build
./autogen.sh
make
sudo make install
```

### Manual Installation

1. Install Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```

2. Install dependencies using Homebrew or MacPorts:
   ```bash
   # Using Homebrew
   brew install autoconf automake libtool openssl libpcap pcre
   
   # Or using MacPorts
   sudo port install autoconf automake libtool openssl libpcap pcre
   ```

3. Build aircrack-ng:
   ```bash
   ./autogen.sh
   make
   sudo make install
   ```

## Permission Setup

### Root Privileges
Most aircrack-ng tools require root privileges to access wireless interfaces:

```bash
sudo airodump-ng en0
```

### Entitlements for Bundled Applications
If you're bundling aircrack-ng tools in an application, you may need to add the following entitlements:
- `com.apple.security.network`

## Usage

### Basic Packet Capture
```bash
# List available interfaces
ifconfig -a

# Capture packets
sudo airodump-ng en0
```

### Channel Hopping
```bash
# Set specific channel
sudo airodump-ng --channel 6 en0

# Hop between channels 1, 6, and 11
sudo airodump-ng --channel 1,6,11 en0
```

## Limitations and Known Issues

### Monitor Mode
- True 802.11 monitor mode is not available through public APIs on macOS
- aircrack-ng uses promiscuous mode through libpcap, which is the closest available option
- Some management frames may be missing from capture

### Packet Injection
- Packet injection is not reliably supported on macOS through public APIs
- Limited support is available through libpcap, but results may vary
- Apple's built-in wireless adapters have particularly limited injection capabilities

### Channel Control
- Channel setting is implemented using the CoreWLAN framework
- Works best when the interface is not associated with a network
- Frequent channel changes may be unreliable

### Hardware Limitations
- Built-in Apple wireless adapters have limited capabilities
- External USB adapters with compatible drivers are recommended
- Not all USB wireless adapters are compatible with macOS

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure you're running commands with `sudo`
   - Check that your user has necessary privileges

2. **Interface Not Found**
   - Verify the interface name with `ifconfig -a`
   - Some interfaces may not be supported

3. **No Packets Captured**
   - Ensure you're on the correct channel
   - Check that the interface supports promiscuous mode

### Debugging

To enable verbose output for debugging:
```bash
export AIRCRACK_NG_DEBUG=1
sudo airodump-ng en0
```

## Compatible Hardware

### Recommended USB Adapters
- Alfa AWUS036ACS
- Panda PAU09
- TP-Link TL-WN722N (version 1.x)

### Built-in Adapters
- Apple Airport cards (limited functionality)
- May not support all aircrack-ng features

## Additional Resources

- [Aircrack-ng Official Documentation](https://aircrack-ng.org)
- [CoreWLAN Framework Reference](https://developer.apple.com/documentation/corewlan)
- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)

## Support

For issues specific to macOS support, please file a GitHub issue with:
- Your macOS version
- The wireless adapter model
- The exact error message
- Steps to reproduce the issue