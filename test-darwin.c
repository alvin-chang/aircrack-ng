/*
 *  Simple test program for macOS wireless implementation
 *  Copyright (c) 2025, Alvin Chang <1977968+alvin-chang@users.noreply.github.com>
 *  Copyright (c) 2025, Qwen-Coder (AI Assistant)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  Authors:
 *    Alvin Chang <1977968+alvin-chang@users.noreply.github.com>
 *    Qwen-Coder (AI Assistant)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "osdep.h"

int main(int argc, char *argv[])
{
    struct wif *wi;
    char *interface;
    unsigned char mac[6];
    int channel, monitor_mode;
    
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\\n", argv[0]);
        return 1;
    }
    
    interface = argv[1];
    
    printf("Testing macOS wireless interface: %s\\n", interface);
    
    // Try to open the interface
    wi = wi_open(interface);
    if (!wi) {
        perror("Failed to open interface");
        return 1;
    }
    
    printf("Successfully opened interface\\n");
    
    // Check if interface is in monitor mode
    monitor_mode = wi_get_monitor(wi);
    printf("Monitor mode: %s\\n", monitor_mode ? "Yes" : "No");
    
    // Try to get MAC address
    if (wi_get_mac(wi, mac) == 0) {
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        printf("Failed to get MAC address: %s\\n", strerror(errno));
    }
    
    // Try to get current channel
    channel = wi_get_channel(wi);
    if (channel > 0) {
        printf("Current Channel: %d\\n", channel);
    } else {
        printf("Failed to get current channel: %s\\n", strerror(errno));
    }
    
    // Try to set channel
    printf("Attempting to set channel to 6...\\n");
    if (wi_set_channel(wi, 6) == 0) {
        printf("Successfully set channel to 6\\n");
        // Verify the channel was set
        channel = wi_get_channel(wi);
        if (channel == 6) {
            printf("Verified: Channel is now %d\\n", channel);
        } else {
            printf("Warning: Channel is now %d, expected 6\\n", channel);
        }
    } else {
        printf("Failed to set channel: %s\\n", strerror(errno));
    }
    
    // Get file descriptor
    int fd = wi_fd(wi);
    if (fd >= 0) {
        printf("File descriptor: %d\\n", fd);
    } else {
        printf("Failed to get file descriptor: %s\\n", strerror(errno));
    }
    
    // Test packet injection (will likely fail)
    printf("Testing packet injection...\\n");
    unsigned char test_packet[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int result = wi_write(wi, NULL, 0, test_packet, sizeof(test_packet), NULL);
    if (result > 0) {
        printf("Successfully sent test packet (%d bytes)\\n", result);
    } else {
        printf("Packet injection failed: %s\\n", strerror(errno));
    }
    
    // Close interface
    wi_close(wi);
    printf("Interface closed\\n");
    
    return 0;
}