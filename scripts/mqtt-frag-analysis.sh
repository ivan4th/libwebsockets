#!/bin/bash
#
# mqtt-frag-analysis.sh
# Identify fragmentation-sensitive code paths in MQTT implementation
#
# This script analyzes the MQTT code to find potential fragmentation bugs
# similar to the one fixed in commit 5719dbe9
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MQTT_DIR="$REPO_ROOT/lib/roles/mqtt"

echo "=============================================="
echo "MQTT Fragmentation-Sensitive Code Analysis"
echo "=============================================="
echo ""
echo "Repository: $REPO_ROOT"
echo "MQTT Directory: $MQTT_DIR"
echo ""

if [ ! -d "$MQTT_DIR" ]; then
    echo "ERROR: MQTT directory not found at $MQTT_DIR"
    exit 1
fi

echo "1. Functions using stateful primitives (potential fragmentation points)"
echo "------------------------------------------------------------------------"
echo ""
echo "These functions call parser primitives that handle fragmented data:"
echo ""
grep -n "lws_mqtt_vbi_r\|lws_mqtt_mb_parse\|lws_mqtt_str_parse" "$MQTT_DIR"/*.c 2>/dev/null || echo "  (none found)"
echo ""

echo "2. State machine transitions (LMQCPP_ states)"
echo "----------------------------------------------"
echo ""
echo "Parser state changes (where fragmentation resumes):"
echo ""
grep -n "par->state = " "$MQTT_DIR/mqtt.c" 2>/dev/null | head -50 || echo "  (none found)"
echo ""

echo "3. Locations checking LMSPR_NEED_MORE (fragmentation handling)"
echo "---------------------------------------------------------------"
echo ""
echo "These are return points where fragmentation is handled:"
echo ""
grep -n "LMSPR_NEED_MORE" "$MQTT_DIR"/*.c 2>/dev/null || echo "  (none found)"
echo ""

echo "4. Parser functions that consume input (potential fragmentation bugs)"
echo "----------------------------------------------------------------------"
echo ""
echo "Input pointer manipulation in primitives.c:"
echo ""
grep -n '\*\*in\|len--\|(\*len)' "$MQTT_DIR/primitives.c" 2>/dev/null || echo "  (none found)"
echo ""

echo "5. Variables that might lose state across fragments"
echo "----------------------------------------------------"
echo ""
echo "Local variables in primitives.c (should be in parser state struct):"
echo ""
grep -n "uint8_t.*=" "$MQTT_DIR/primitives.c" 2>/dev/null | grep -v "const\|static\|multiplier = (uint8_t)(7" || echo "  (none found - good!)"
echo ""

echo "6. State tracking in parser primitives"
echo "--------------------------------------"
echo ""
echo "Checking for proper state tracking (vbi->consumed, s->pos, etc.):"
echo ""

for func in lws_mqtt_vbi_r lws_mqtt_mb_parse lws_mqtt_str_parse; do
    echo "  $func:"
    if grep -A 30 "^$func\|^lws_mqtt_stateful.*$func" "$MQTT_DIR/primitives.c" 2>/dev/null | grep -q "consumed\|\.pos"; then
        echo "    [OK] Has state tracking (consumed/pos)"
    else
        echo "    [WARNING] May need state tracking review"
    fi
done
echo ""

echo "7. Potential issues: local variables in loops"
echo "----------------------------------------------"
echo ""
echo "Looking for loop-scoped variables that should persist:"
echo ""
grep -B 2 -A 10 "while.*len\|while.*budget" "$MQTT_DIR/primitives.c" 2>/dev/null | \
    grep -E "^\s+uint8_t\s+\w+\s*=" | \
    grep -v "multiplier = (uint8_t)(7" || echo "  (none found - good!)"
echo ""

echo "8. Summary of MQTT parser state structures"
echo "------------------------------------------"
echo ""
echo "Key structures in private-lib-roles-mqtt.h:"
echo ""
grep -n "^typedef struct\|^} lws_mqtt" "$MQTT_DIR/private-lib-roles-mqtt.h" 2>/dev/null | head -20 || echo "  (none found)"
echo ""

echo "9. Functions that need fragmentation testing"
echo "--------------------------------------------"
echo ""
echo "These functions should have unit tests with fragmented input:"
echo ""
grep -E "^(void|int|lws_mqtt_stateful_primitive_return_t)\s+lws_mqtt_" "$MQTT_DIR/primitives.c" 2>/dev/null | \
    sed 's/(.*//; s/^/  - /' || echo "  (none found)"
echo ""

echo "=============================================="
echo "Analysis Complete"
echo "=============================================="
echo ""
echo "Recommendations:"
echo "  1. Unit test all functions listed in section 9"
echo "  2. Test with single-byte fragmentation"
echo "  3. Test with random chunk sizes"
echo "  4. Review any warnings from sections 5-7"
echo ""
