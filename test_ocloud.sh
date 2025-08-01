#!/bin/bash

# Test script for ocloud CLI
# This script tests various combinations of commands and flags for the ocloud CLI

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Array to store errors
errors=()

# Function to print section headers
print_header() {
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
    echo ""
}

# Function to run a command and print the command before executing
# Captures exit code and displays errors in red
run_command() {
    echo "$ $@"
    "$@"
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        # Print error message in red
        echo -e "${RED}Command failed with exit code $exit_code${NC}"

        # Store the error for summary - concatenate all args into a single string
        cmd_str="Command failed: $(printf "%s " "$@")"
        errors+=("${cmd_str%?}")  # Remove trailing space
    fi

    echo ""
}

# Test version command and flag
print_header "Testing version command and flag"
run_command ./bin/ocloud version
run_command ./bin/ocloud -v
run_command ./bin/ocloud --version

# Test root command with help
print_header "Testing root command with help"
run_command ./bin/ocloud --help

# Test config info map-file command
print_header "Testing config info map-file command"
run_command ./bin/ocloud config info map-file
run_command ./bin/ocloud config info map-file --json
run_command ./bin/ocloud config info map-file --realm OC1
run_command ./bin/ocloud config info map-file --realm OC1 --json

# Test root command with global flags
print_header "Testing root command with global flags"
run_command ./bin/ocloud --compartment $OCI_COMPARTMENT
run_command ./bin/ocloud -c $OCI_COMPARTMENT

# Test compute command
print_header "Testing compute command"
run_command ./bin/ocloud compute --help
run_command ./bin/ocloud comp --help

# Test compute instance command
print_header "Testing compute instance command"
run_command ./bin/ocloud compute instance --help
run_command ./bin/ocloud comp inst --help

# Test compute instance list command
print_header "Testing compute instance list command"
run_command ./bin/ocloud compute instance list
run_command ./bin/ocloud compute instance list
run_command ./bin/ocloud compute instance list --limit 10 --page 1 --json
run_command ./bin/ocloud compute instance list -m 10 -p 1 -j
run_command ./bin/ocloud comp inst l

# Test compute instance find command
print_header "Testing compute instance find command"
run_command ./bin/ocloud compute instance find "roster"
run_command ./bin/ocloud compute instance find "roster"
run_command ./bin/ocloud compute instance find "roster" --all --json
run_command ./bin/ocloud compute instance find "roster" -A -j
run_command ./bin/ocloud comp inst f "roster"

# Test compute image command
print_header "Testing compute image command"
run_command ./bin/ocloud compute image --help
run_command ./bin/ocloud comp img --help

# Test compute image list command
print_header "Testing compute image list command"
run_command ./bin/ocloud compute image list
run_command ./bin/ocloud compute image list
run_command ./bin/ocloud compute image list --limit 10 --page 1 --json
run_command ./bin/ocloud compute image list -m 10 -p 1 -j
run_command ./bin/ocloud comp img l

# Test compute image find command
print_header "Testing compute image find command"
run_command ./bin/ocloud compute image find "ubuntu"
run_command ./bin/ocloud compute image find "ubuntu"
run_command ./bin/ocloud compute image find "ubuntu" --json
run_command ./bin/ocloud compute image find "ubuntu" -j
run_command ./bin/ocloud comp img f "ubuntu"

# Test compute oke command
print_header "Testing compute oke command"
run_command ./bin/ocloud compute oke --help
run_command ./bin/ocloud comp oke --help

# Test compute oke list command
print_header "Testing compute oke list command"
run_command ./bin/ocloud compute oke list
run_command ./bin/ocloud compute oke list
run_command ./bin/ocloud compute oke list --limit 10 --page 1 --json
run_command ./bin/ocloud compute oke list -m 10 -p 1 -j
run_command ./bin/ocloud comp oke l

# Test compute oke find command
print_header "Testing compute oke find command"
run_command ./bin/ocloud compute oke find "orion"
run_command ./bin/ocloud compute oke find "orion"
run_command ./bin/ocloud compute oke find "orion" --json
run_command ./bin/ocloud compute oke find "orion" -j
run_command ./bin/ocloud comp oke f "orion"

# Test with debug flag
print_header "Testing with debug flag"
run_command ./bin/ocloud -d compute instance list
run_command ./bin/ocloud --debug compute instance list

# Test with color flag
print_header "Testing with color flag"
run_command ./bin/ocloud --color compute instance list

# Test with disable concurrency flag
print_header "Testing with disable concurrency flag"
run_command ./bin/ocloud -x compute instance list
run_command ./bin/ocloud --disable-concurrency compute instance list

# Test identity command
print_header "Testing identity command"
run_command ./bin/ocloud identity --help
run_command ./bin/ocloud ident --help
run_command ./bin/ocloud idt --help

# Test identity compartment command
print_header "Testing identity compartment command"
run_command ./bin/ocloud identity compartment --help
run_command ./bin/ocloud identity compart --help
run_command ./bin/ocloud ident compart --help

# Test identity compartment list command
print_header "Testing identity compartment list command"
run_command ./bin/ocloud identity compartment list
run_command ./bin/ocloud identity compartment list
run_command ./bin/ocloud identity compartment list --limit 10 --page 1 --json
run_command ./bin/ocloud identity compartment list -m 10 -p 1 -j
run_command ./bin/ocloud ident compart l

# Test identity compartment find command
print_header "Testing identity compartment find command"
run_command ./bin/ocloud identity compartment find "sand"
run_command ./bin/ocloud identity compartment find "sand"
run_command ./bin/ocloud identity compartment find "sand" --json
run_command ./bin/ocloud identity compartment find "sand" -j
run_command ./bin/ocloud ident compart f "sand"

# Test identity policy command
print_header "Testing identity policy command"
run_command ./bin/ocloud identity policy --help
run_command ./bin/ocloud identity pol --help
run_command ./bin/ocloud ident pol --help

# Test identity policy list command
print_header "Testing identity policy list command"
run_command ./bin/ocloud identity policy list
run_command ./bin/ocloud identity policy list
run_command ./bin/ocloud identity policy list --limit 10 --page 1 --json
run_command ./bin/ocloud identity policy list -m 10 -p 1 -j
run_command ./bin/ocloud ident pol l

# Test identity policy find command
print_header "Testing identity policy find command"
run_command ./bin/ocloud identity policy find "monitor"
run_command ./bin/ocloud identity policy find "monitor"
run_command ./bin/ocloud identity policy find "monitor" --json
run_command ./bin/ocloud identity policy find "monitor" -j
run_command ./bin/ocloud ident pol f "monitor"

# Test network command
print_header "Testing network command"
run_command ./bin/ocloud network --help
run_command ./bin/ocloud net --help

# Test network subnet command
print_header "Testing network subnet command"
run_command ./bin/ocloud network subnet --help
run_command ./bin/ocloud network sub --help
run_command ./bin/ocloud net sub --help

# Test network subnet list command
print_header "Testing network subnet list command"
run_command ./bin/ocloud network subnet list
run_command ./bin/ocloud network subnet list
run_command ./bin/ocloud network subnet list --limit 10 --page 1 --json
run_command ./bin/ocloud network subnet list -m 10 -p 1 -j
run_command ./bin/ocloud net sub l

# Test network subnet find command
print_header "Testing network subnet find command"
run_command ./bin/ocloud network subnet find "pub"
run_command ./bin/ocloud network subnet find "pub"
run_command ./bin/ocloud network subnet find "pub" --json
run_command ./bin/ocloud network subnet find "pub" -j
run_command ./bin/ocloud net sub f "pub"

# Test database command
print_header "Testing database command"
run_command ./bin/ocloud database --help
run_command ./bin/ocloud db --help

# Test database autonomousdb command
print_header "Testing database autonomousdb command"
run_command ./bin/ocloud database autonomous --help
run_command ./bin/ocloud database adb --help
run_command ./bin/ocloud db adb --help

# Test database autonomousdb list command
print_header "Testing database autonomousdb list command"
run_command ./bin/ocloud database autonomous list
run_command ./bin/ocloud database autonomous list
run_command ./bin/ocloud database autonomous list --limit 10 --page 1 --json
run_command ./bin/ocloud database autonomous list -m 10 -p 1 -j
run_command ./bin/ocloud db adb l

# Test database autonomousdb find command
print_header "Testing database autonomousdb find command"
run_command ./bin/ocloud database autonomous find "test"
run_command ./bin/ocloud database autonomous find "test"
run_command ./bin/ocloud database autonomous find "test" --json
run_command ./bin/ocloud database autonomous find "test" -j
run_command ./bin/ocloud db adb f "test"

print_header "All tests completed"

# Display error summary if there were any errors
if [ ${#errors[@]} -gt 0 ]; then
    echo -e "${RED}ERROR SUMMARY:${NC}"
    echo -e "${RED}=============${NC}"
    for error in "${errors[@]}"; do
        echo -e "${RED}$error${NC}"
    done
    echo ""
    echo -e "${RED}Total errors: ${#errors[@]}${NC}"
    exit 1
else
    echo -e "${GREEN}All commands completed successfully!${NC}"
fi
