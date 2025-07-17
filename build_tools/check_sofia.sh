#!/bin/bash
# Check for Sofia-SIP library

if pkg-config --exists sofia-sip-ua 2>/dev/null; then
    echo "SOFIA_INCLUDE=$(pkg-config --cflags sofia-sip-ua)"
    echo "SOFIA_LIB=$(pkg-config --libs sofia-sip-ua)"
    echo "SOFIA_FOUND=yes"
else
    echo "# Sofia-SIP not found"
    echo "SOFIA_FOUND=no"
fi