# macOS Wireless Support Implementation Plan for Aircrack-ng

## 1. Specific, Achievable Goals for Initial Implementation Phase

Based on the feasibility analysis, the initial implementation phase will focus on achieving the following goals:

1. **Basic Packet Capture**: Implement `wi_read` functionality using libpcap/BPF for capturing 802.11 frames in promiscuous mode.
2. **Interface Initialization**: Implement `wi_open_osdep` to initialize wireless interfaces on macOS.
3. **Channel Control**: Implement basic `wi_set_channel` and `wi_get_channel` using CoreWLAN framework where available.
4. **Interface Information**: Implement `wi_get_mac` to retrieve MAC addresses of wireless interfaces.
5. **File Descriptor Access**: Implement `wi_fd` to provide file descriptor for select() operations.
6. **Error Handling**: Proper error handling with appropriate errno values for unsupported operations.

## 2. Steps to Modify or Create Files in `lib/osdep/`

### 2.1 Primary Implementation Files

1. **`lib/osdep/darwin.c`** (existing file to be enhanced):
   - Replace the current stub implementation with full functionality
   - Implement all required `wi_*` functions
   - Add macOS-specific private data structures

2. **`lib/osdep/darwin_tap.c`** (existing file, may need minor updates):
   - Verify TAP interface support works correctly on macOS
   - Update if necessary for compatibility with new wireless implementation

### 2.2 Header Files

3. **`include/aircrack-ng/osdep/osdep.h`** (existing file, no changes needed):
   - Verify all required function signatures are present
   - No modifications needed as the interface is already defined

### 2.3 Helper Files

4. **`lib/osdep/common.c`** (existing file, no changes needed):
   - Reuse existing helper functions like `getChannelFromFrequency` and `getFrequencyFromChannel`

## 3. Implementation of Core Functions in `darwin.c`

### 3.1 Data Structures

```c
// Private data structure for macOS wireless interface
struct priv_darwin {
    int fd;                      // File descriptor for BPF device
    char device[IFNAMSIZ];       // Interface name
    unsigned char mac[6];        // MAC address
    int channel;                 // Current channel
    int frequency;               // Current frequency
    char bpf_device[32];         // BPF device path
    pcap_t *pcap_handle;         // libpcap handle for packet capture
    int pcap_fd;                 // File descriptor from libpcap
};
```

### 3.2 Core Function Implementations

#### 3.2.1 `wi_open_osdep`
```c
struct wif * wi_open_osdep(char * iface)
{
    struct wif * wi;
    struct priv_darwin * pd;
    
    // Allocate wif structure
    wi = wi_alloc(sizeof(*pd));
    if (!wi) return NULL;
    
    // Set up function pointers
    wi->wi_read = darwin_read;
    wi->wi_write = darwin_write;
    wi->wi_set_channel = darwin_set_channel;
    wi->wi_get_channel = darwin_get_channel;
    wi->wi_set_freq = darwin_set_freq;
    wi->wi_get_freq = darwin_get_freq;
    wi->wi_close = darwin_close;
    wi->wi_fd = darwin_fd;
    wi->wi_get_mac = darwin_get_mac;
    wi->wi_set_mac = darwin_set_mac;
    wi->wi_set_rate = darwin_set_rate;
    wi->wi_get_rate = darwin_get_rate;
    
    // Initialize private data
    pd = wi_priv(wi);
    strncpy(pd->device, iface, IFNAMSIZ - 1);
    pd->device[IFNAMSIZ - 1] = '\0';
    pd->channel = -1;
    pd->frequency = -1;
    
    // Initialize interface
    if (do_darwin_open(wi, iface) != 0) {
        wi_close(wi);
        return NULL;
    }
    
    return wi;
}
```

#### 3.2.2 `darwin_read` (Packet Capture)
```c
int darwin_read(struct wif * wi, struct timespec * ts, int * dlt,
                unsigned char * h80211, int len, struct rx_info * ri)
{
    struct priv_darwin * pd = wi_priv(wi);
    struct pcap_pkthdr *header;
    const u_char *packet;
    int ret;
    
    // Use libpcap to capture packets
    ret = pcap_next_ex(pd->pcap_handle, &header, &packet);
    
    if (ret == 1) {
        // Successfully captured a packet
        if (header->caplen > len) {
            errno = EOVERFLOW;
            return -1;
        }
        
        // Copy packet data
        memcpy(h80211, packet, header->caplen);
        
        // Set data link type
        *dlt = pcap_datalink(pd->pcap_handle);
        
        // Set timestamp
        if (ts) {
            ts->tv_sec = header->ts.tv_sec;
            ts->tv_nsec = header->ts.tv_usec * 1000;
        }
        
        // Populate rx_info if provided
        if (ri) {
            memset(ri, 0, sizeof(*ri));
            ri->ri_power = -1;  // Not available through libpcap
            ri->ri_noise = -1;  // Not available through libpcap
            ri->ri_channel = pd->channel;
            ri->ri_freq = pd->frequency;
            ri->ri_mactime = 0; // Not available through libpcap
        }
        
        return header->caplen;
    } else if (ret == 0) {
        // Timeout
        errno = EAGAIN;
        return -1;
    } else {
        // Error
        errno = EIO;
        return -1;
    }
}
```

#### 3.2.3 `darwin_set_channel`
```c
int darwin_set_channel(struct wif * wi, int chan)
{
    struct priv_darwin * pd = wi_priv(wi);
    
#ifdef HAVE_COREWLAN
    // Use CoreWLAN framework if available
    return corewlan_set_channel(pd->device, chan);
#else
    // Fallback: Use ioctl or other methods
    // Note: This will have limitations on modern macOS
    pd->channel = chan;
    pd->frequency = getFrequencyFromChannel(chan);
    return 0;
#endif
}
```

#### 3.2.4 `darwin_get_channel`
```c
int darwin_get_channel(struct wif * wi)
{
    struct priv_darwin * pd = wi_priv(wi);
    
#ifdef HAVE_COREWLAN
    // Use CoreWLAN framework if available
    return corewlan_get_channel(pd->device);
#else
    // Return cached value
    return pd->channel;
#endif
}
```

#### 3.2.5 `darwin_fd`
```c
int darwin_fd(struct wif * wi)
{
    struct priv_darwin * pd = wi_priv(wi);
    return pd->pcap_fd;
}
```

#### 3.2.6 `darwin_get_mac`
```c
int darwin_get_mac(struct wif * wi, unsigned char * mac)
{
    struct priv_darwin * pd = wi_priv(wi);
    struct ifreq ifr;
    int fd;
    
    // If we already have the MAC, return it
    if (pd->mac[0] || pd->mac[1] || pd->mac[2] || 
        pd->mac[3] || pd->mac[4] || pd->mac[5]) {
        memcpy(mac, pd->mac, 6);
        return 0;
    }
    
    // Get MAC address using ioctl
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pd->device, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    memcpy(pd->mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    
    return 0;
}
```

## 4. Build System Changes

### 4.1 `configure.ac` Modifications

Add detection for required macOS frameworks and libraries:

```autoconf
# Check for CoreWLAN framework (macOS)
AC_MSG_CHECKING([for CoreWLAN framework])
if test "x$DARWIN" = "xyes"; then
    AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([
            #include <CoreWLAN/CoreWLAN.h>
        ], [
            CWInterface* iface = NULL;
        ])
    ], [
        AC_DEFINE([HAVE_COREWLAN], [1], [Define if CoreWLAN framework is available])
        COREWLAN_LIBS="-framework CoreWLAN -framework Foundation"
        AC_SUBST([COREWLAN_LIBS])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
fi

# Check for libpcap
AC_CHECK_LIB([pcap], [pcap_open_live], [
    PCAP_LIBS="-lpcap"
    AC_SUBST([PCAP_LIBS])
], [
    AC_MSG_ERROR([libpcap library not found])
])

AC_CHECK_HEADERS([pcap/pcap.h pcap/bpf.h])
```

### 4.2 `lib/osdep/Makefile.inc` Modifications

Update the DARWIN section to include required libraries:

```makefile
if DARWIN
libaircrack_osdep_la_SOURCES = $(SRCS_DARWIN)
libaircrack_osdep_la_LIBADD = $(LIBRADIOTAP_LIBS) $(PCAP_LIBS) $(COREWLAN_LIBS)
endif
```

## 5. Testing Strategy

### 5.1 Unit Testing Approach

1. **Basic Functionality Tests**:
   - Test `wi_open_osdep` with valid and invalid interface names
   - Test `wi_get_mac` returns correct MAC addresses
   - Test `wi_fd` returns valid file descriptors

2. **Packet Capture Tests**:
   - Test `wi_read` can capture packets (requires root privileges)
   - Verify correct packet data and metadata are returned
   - Test timeout handling

3. **Channel Control Tests**:
   - Test `wi_set_channel` and `wi_get_channel` functionality
   - Verify channel changes are properly tracked

### 5.2 Integration Testing

1. **Airodump-ng Integration**:
   - Test basic packet capture with airodump-ng
   - Verify compatibility with existing aircrack-ng tools

2. **Root Privilege Handling**:
   - Test proper error messages when run without sufficient privileges
   - Verify graceful degradation when certain features are unavailable

### 5.3 Root Privilege Management

1. **Capability Detection**:
   - At runtime, check if the process has necessary privileges
   - Provide clear error messages when privileges are insufficient

2. **Sandbox Detection**:
   - Detect if running in a sandboxed environment
   - Provide guidance for users on required permissions

## 6. Security and Permission Handling

### 6.1 Required Permissions

1. **Root/Administrative Privileges**:
   - Required for accessing BPF devices
   - Required for channel setting operations
   - Required for packet capture

2. **Entitlements** (for bundled applications):
   - `com.apple.security.network` for network access
   - Custom entitlements for private framework access (if needed)

### 6.2 Permission Request Strategy

1. **Runtime Checks**:
   - Check for necessary permissions at startup
   - Provide clear error messages with resolution steps

2. **User Guidance**:
   - Document required permissions in README
   - Provide examples of how to grant permissions

### 6.3 Error Handling

1. **Graceful Degradation**:
   - When certain features are unavailable, provide informative error messages
   - Fall back to supported functionality where possible

2. **Security Violations**:
   - Handle permission denials gracefully
   - Guide users to documentation for resolving permission issues

## 7. Limitations and Caveats

### 7.1 Platform Limitations

1. **Monitor Mode Restrictions**:
   - True 802.11 monitor mode is not available through public APIs
   - Limited to promiscuous mode capture
   - Some management frames may be missing

2. **Packet Injection Limitations**:
   - No reliable packet injection support through public APIs
   - Private APIs exist but are undocumented and unstable

3. **Channel Hopping Limitations**:
   - Dynamic channel hopping while maintaining capture is challenging
   - CoreWLAN has limitations for frequent channel changes

### 7.2 Hardware Limitations

1. **Built-in Adapters**:
   - Apple's built-in wireless adapters have limited capabilities
   - May not support all required features

2. **External Adapters**:
   - Recommend using external USB adapters with compatible drivers
   - Better compatibility with standard 802.11 monitoring tools

### 7.3 API Stability

1. **Private Frameworks**:
   - Apple80211 framework is undocumented and subject to change
   - Not recommended for production use

2. **Framework Updates**:
   - CoreWLAN APIs may change between macOS versions
   - Need to test with each new macOS release

## 8. Implementation Roadmap

### Phase 1: Basic Packet Capture (2-3 weeks)
- Implement `wi_open_osdep`, `wi_read`, `wi_fd`, `wi_get_mac`
- Integrate libpcap for packet capture
- Basic error handling and testing

### Phase 2: Channel Control (1-2 weeks)
- Implement `wi_set_channel` and `wi_get_channel`
- Integrate CoreWLAN framework for channel control
- Testing with various wireless interfaces

### Phase 3: Enhanced Features (2-3 weeks)
- Implement remaining functions (`wi_write`, `wi_set_freq`, etc.)
- Research private API options for advanced features
- Comprehensive testing and documentation

### Phase 4: Validation and Optimization (1-2 weeks)
- Integration testing with aircrack-ng tools
- Performance optimization
- Documentation and user guides

## 9. Documentation Requirements

1. **User Documentation**:
   - Installation requirements for macOS
   - Permission setup instructions
   - Compatible hardware list

2. **Developer Documentation**:
   - Code structure and design decisions
   - API usage examples
   - Testing procedures

3. **Troubleshooting Guide**:
   - Common issues and solutions
   - Permission error resolution
   - Compatibility matrix

This implementation plan provides a structured approach to adding macOS wireless support to aircrack-ng, focusing first on achievable goals while acknowledging platform limitations.