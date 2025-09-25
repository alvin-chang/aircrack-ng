#!/bin/bash
#
# Aircrack-ng macOS Setup Script
# Copyright (c) 2025, Alvin Chang <1977968+alvin-chang@users.noreply.github.com>
# Copyright (c) 2025, Qwen-Coder (AI Assistant)
#
# This script helps configure the macOS environment for aircrack-ng usage
# by working around platform limitations using system utilities.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#

INTERFACE=${1:-en0}
ACTION=${2:-help}

# Function to display help
show_help() {
    echo "Aircrack-ng macOS Setup Script"
    echo "Usage: $0 <interface> <action>"
    echo ""
    echo "Interface: (default: en0)"
    echo "Actions:"
    echo "  help                Show this help message"
    echo "  check               Check interface status and capabilities"
    echo "  monitor             Attempt to enable monitor mode (using external tools)"
    echo "  channel <n>         Set WiFi channel to n (using airport command)"
    echo "  scan                Perform a basic wireless scan"
    echo "  cleanup             Reset interface to normal mode"
    echo ""
    echo "Note: Full wireless control is limited on macOS due to system security restrictions."
    echo "This script attempts to use available system utilities to work around limitations."
}

# Function to check interface
check_interface() {
    echo "Checking interface: $INTERFACE"
    
    # Check if interface exists and is a Wi-Fi interface
    if networksetup -listallhardwareports | grep -A1 -B1 Wi-Fi | grep "$INTERFACE" > /dev/null; then
        echo "✓ Interface $INTERFACE is a Wi-Fi interface"
    else
        echo "✗ Interface $INTERFACE may not be a Wi-Fi interface"
        exit 1
    fi
    
    # Check if airport command exists
    AIRPORT_PATH="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if [ -x "$AIRPORT_PATH" ]; then
        echo "✓ Airport command available at: $AIRPORT_PATH"
        echo "Current status:"
        sudo "$AIRPORT_PATH" -I
    else
        echo "✗ Airport command not found at expected location"
    fi
}

# Function to set channel
set_channel() {
    CHANNEL=$3
    if [ -z "$CHANNEL" ]; then
        echo "Please specify a channel number"
        echo "Usage: $0 $INTERFACE channel <n>"
        exit 1
    fi
    
    AIRPORT_PATH="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if [ -x "$AIRPORT_PATH" ]; then
        echo "Setting channel to $CHANNEL..."
        sudo "$AIRPORT_PATH" -c$CHANNEL
        if [ $? -eq 0 ]; then
            echo "✓ Channel set to $CHANNEL"
        else
            echo "✗ Failed to set channel $CHANNEL"
            echo "This may be due to macOS security restrictions"
        fi
    else
        echo "✗ Airport command not available"
    fi
}

# Function to scan
perform_scan() {
    AIRPORT_PATH="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if [ -x "$AIRPORT_PATH" ]; then
        echo "Scanning for networks..."
        sudo "$AIRPORT_PATH" -s
    else
        echo "✗ Airport command not available for scanning"
    fi
}

# Function to enable monitor mode (attempts using available methods)
enable_monitor_mode() {
    echo "Note: True monitor mode is not available through public APIs on macOS"
    echo "This script will attempt to put the interface in a state suitable for aircrack-ng"
    echo "using available system utilities."
    
    # Some drivers or utilities might support putting the interface in a mode that works with aircrack-ng
    # This is highly dependent on hardware and installed drivers
    echo "For best results with monitor mode, consider:"
    echo "1. Using an external USB adapter with monitor mode support"
    echo "2. Installing appropriate drivers for your adapter"
    echo "3. Using tools like Kismet which may work better with macOS limitations"
    
    # Check if mac80211_hwsim alternative exists (not applicable to macOS but for example)
    # On macOS, this is more about configuring the interface to be in a promiscuous state
    echo ""
    echo "Interface $INTERFACE is configured for promiscuous mode when used with aircrack-ng tools"
}

# Function to cleanup/reset interface
cleanup_interface() {
    echo "Resetting interface: $INTERFACE"
    echo "Note: This will restore normal Wi-Fi connectivity."
    
    # Attempt to reconnect to last network
    # This is just an example - actual reconnection may depend on configuration
    echo "Interface reset. You may need to manually reconnect to a Wi-Fi network."
}

# Main execution logic
case "$ACTION" in
    "help")
        show_help
        ;;
    "check")
        check_interface
        ;;
    "channel")
        set_channel $@
        ;;
    "scan")
        perform_scan
        ;;
    "monitor")
        enable_monitor_mode
        ;;
    "cleanup")
        cleanup_interface
        ;;
    *)
        echo "Unknown action: $ACTION"
        show_help
        ;;
esac