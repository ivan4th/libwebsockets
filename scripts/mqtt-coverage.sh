#!/bin/bash
#
# mqtt-coverage.sh
# Generate code coverage report for MQTT tests
#
# Usage: ./scripts/mqtt-coverage.sh [build-dir]
#
# Prerequisites:
#   - Build with coverage enabled:
#     cmake .. -DLWS_WITH_COVERAGE=ON -DLWS_ROLE_MQTT=1
#   - lcov and genhtml installed
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${1:-$REPO_ROOT/build}"
OUTPUT_DIR="$REPO_ROOT/coverage-report"

echo "=============================================="
echo "MQTT Coverage Analysis"
echo "=============================================="
echo ""
echo "Repository: $REPO_ROOT"
echo "Build Directory: $BUILD_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Check prerequisites
if ! command -v lcov &> /dev/null; then
    echo "ERROR: lcov not found. Install with: apt-get install lcov"
    exit 1
fi

if ! command -v genhtml &> /dev/null; then
    echo "ERROR: genhtml not found. Install with: apt-get install lcov"
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "ERROR: Build directory not found: $BUILD_DIR"
    echo ""
    echo "First, build with coverage enabled:"
    echo "  mkdir -p build && cd build"
    echo "  cmake .. -DLWS_WITH_COVERAGE=ON -DLWS_ROLE_MQTT=1 -DLWS_WITH_MINIMAL_EXAMPLES=1"
    echo "  make -j\$(nproc)"
    exit 1
fi

cd "$BUILD_DIR"

echo "Step 1: Reset coverage counters"
echo "--------------------------------"
lcov --zerocounters --directory . --quiet
echo "Done."
echo ""

echo "Step 2: Run MQTT tests"
echo "----------------------"
if ctest -R mqtt --output-on-failure 2>&1; then
    echo "Tests completed."
else
    echo "Some tests failed, but continuing with coverage analysis..."
fi
echo ""

echo "Step 3: Capture coverage data"
echo "-----------------------------"
lcov --capture --directory . --output-file mqtt-coverage.info --quiet
echo "Captured coverage data."
echo ""

echo "Step 4: Filter to MQTT files only"
echo "----------------------------------"
lcov --extract mqtt-coverage.info \
    '*/lib/roles/mqtt/*' \
    --output-file mqtt-only.info --quiet

# Also try to include test files if they exist
lcov --extract mqtt-coverage.info \
    '*/api-test-mqtt*/*' \
    --output-file test-only.info --quiet 2>/dev/null || true

# Combine if test coverage exists
if [ -s test-only.info ]; then
    lcov --add-tracefile mqtt-only.info \
         --add-tracefile test-only.info \
         --output-file combined.info --quiet
    mv combined.info mqtt-only.info
fi

echo "Filtered to MQTT-related files."
echo ""

echo "Step 5: Generate HTML report"
echo "----------------------------"
mkdir -p "$OUTPUT_DIR"
genhtml mqtt-only.info --output-directory "$OUTPUT_DIR" --quiet
echo "HTML report generated."
echo ""

echo "Step 6: Coverage Summary"
echo "------------------------"
lcov --summary mqtt-only.info
echo ""

echo "=============================================="
echo "Coverage Analysis Complete"
echo "=============================================="
echo ""
echo "View the report:"
echo "  open $OUTPUT_DIR/index.html"
echo ""
echo "Or on Linux:"
echo "  xdg-open $OUTPUT_DIR/index.html"
echo ""

# Print per-file summary
echo "Per-file coverage:"
echo "------------------"
lcov --list mqtt-only.info 2>/dev/null | tail -20 || true
