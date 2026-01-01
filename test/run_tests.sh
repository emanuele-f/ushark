#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall test status
FAILED_TESTS=0
PASSED_TESTS=0
CREATED_OUTPUTS=0

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find all test directories under the script's directory
for test_dir in "$SCRIPT_DIR"/*/; do
    # Skip if not a directory
    [ -d "$test_dir" ] || continue

    echo "Running tests in $test_dir"

    # Find all .pcap files in this directory
    for pcap_file in "$test_dir"*.pcap; do
        # Skip if no pcap files found
        [ -f "$pcap_file" ] || continue

        # Get the base name without extension
        base_name=$(basename "$pcap_file" .pcap)
        expected_out="${test_dir}${base_name}.out"

        # Build the command (relative to project root, which is parent of script dir)
        PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
        cmd="$PROJECT_ROOT/libushark/pcap_example --http2 -s -f $pcap_file"

        # Add -k parameter if keys.txt exists in the directory
        keys_file="${test_dir}keys.txt"
        if [ -f "$keys_file" ]; then
            cmd="$cmd -k $keys_file"
        fi

        echo "Testing: $pcap_file"

        # Run the command and capture output
        actual_output=$(eval "$cmd" 2>&1)
        if [ $? -ne 0 ]; then
          echo -e "$actual_output" >&2
          exit 1
        fi

        # Check if expected output file exists
        if [ ! -f "$expected_out" ]; then
            echo -e "${YELLOW}WARNING: Expected output file $expected_out not found. Creating it.${NC}"
            echo "$actual_output" > "$expected_out"
            CREATED_OUTPUTS=$((CREATED_OUTPUTS + 1))

            # Verify the output is deterministic by running again
            verify_output=$(eval "$cmd" 2>&1)
            if [ "$actual_output" = "$verify_output" ]; then
                echo -e "${GREEN}✓ PASSED (verified deterministic)${NC}"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo -e "${RED}✗ WARNING: Output is non-deterministic!${NC}"
                echo "First run differs from second run for $pcap_file"
            fi
            continue
        fi

        # Compare actual output with expected output
        expected_output=$(cat "$expected_out")

        if [ "$actual_output" = "$expected_output" ]; then
            echo -e "${GREEN}✓ PASSED${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}✗ FAILED${NC}"
            echo "Output differs from expected for $pcap_file"
            echo "Expected output file: $expected_out"
            echo ""
            echo "Diff:"
            diff -u "$expected_out" <(echo "$actual_output") || true
            echo ""
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    done
done

# Print summary
echo ""
echo "========== Test Summary =========="
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $CREATED_OUTPUTS -gt 0 ]; then
    echo -e "${YELLOW}Created: $CREATED_OUTPUTS${NC}"
fi
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
fi
echo "=================================="

# Exit with error if any tests failed
if [ $FAILED_TESTS -gt 0 ]; then
    exit 1
fi

exit 0
