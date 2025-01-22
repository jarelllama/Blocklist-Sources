#!/bin/bash

# Retrieves domains from the various sources and builds the respective
# blocklist.

readonly DOMAIN_REGEX='[[:alnum:]][[:alnum:].-]*[[:alnum:]]\.[[:alnum:]-]*[a-z]{2,}[[:alnum:]-]*'

source_gridinsoft() {
    local url='https://gridinsoft.com/website-reputation-checker'

    # Some entries have '_' instead of '-' in the domain name
    curl -sS --retry 2 --retry-all-errors "$url" \
        | grep -Po "online-virus-scanner/url/\K[[:alnum:].-_]+-[[:alnum:]-]+(?=\".*--suspicious\">)" \
        | mawk '{gsub(/_/, "-"); gsub(/-/, "."); print}' >> gridinsoft.txt

    build gridinsoft.txt
}

source_easydmarc() {
    local url='https://easydmarc.com/tools/phishing-url'

    curl -sS --retry 2 --retry-all-errors "$url" \
        | grep -Po "https://\K${DOMAIN_REGEX}(?=(/[^/]+)*</a></td><td><span class=\"eas-tag eas-tag--standard eas-tag--red\">SUSPICIOUS)" \
        >> easydmarc.txt

    build easydmarc.txt
}

# Function 'build' formats the blocklist passed.
# Input:
#   $1: unformatted blocklist to format
# Output:
#   Formatted blocklist
build() {
    # Compile list. See the list of transformations here:
    # https://github.com/AdguardTeam/HostlistCompiler
    # Note the hostlist compiler removes the previous comments and the Adblock
    # Plus header.
    printf "\n"
    hostlist-compiler -i "$1" -o compiled.tmp

    # Remove comments
    sed -i '/!/d' compiled.tmp

    # Sort since the hostlist compiler does not sort the domains
    sort -u compiled.tmp -o compiled.tmp

    # Remove dead domains
    #printf "\n"
    #dead-domains-linter -a -i compiled.tmp

    # Deploy blocklist
    append_header "$1"
    cat compiled.tmp >> "$1"
}

# Function 'append_header' appends the Adblock Plus header to the blocklist.
# Input:
#   $1: blocklist to append header to
append_header() {
    cat << EOF > "$1"
[Adblock Plus]
! Title: Blocklist to be used as a source for https://github.com/jarelllama/Scam-Blocklist
! Description: Domains scraped every thirty minutes to be used in https://github.com/jarelllama/Scam-Blocklist.
! Homepage: https://github.com/jarelllama/Blocklist-Sources
! License: https://github.com/jarelllama/Blocklist-Sources/blob/main/LICENSE
! Version: $(date -u +"%m.%d.%H%M%S.%Y")
! Expires: 30 minutes
! Last modified: $(date -u)
! Syntax: Adblock Plus
! Number of entries: $(wc -l < compiled.tmp)
EOF
}

cleanup() {
    find . -maxdepth 1 -type f -name "*.tmp" -delete
}

# Entry point

trap cleanup EXIT

# Install AdGuard's Dead Domains Linter
if ! command -v dead-domains-linter &> /dev/null; then
    npm install -g @adguard/dead-domains-linter > /dev/null
fi

# Install AdGuard's Hostlist Compiler
if ! command -v hostlist-compiler &> /dev/null; then
    npm install -g @adguard/hostlist-compiler > /dev/null
fi

set -e

source_gridinsoft

#source_easydmarc