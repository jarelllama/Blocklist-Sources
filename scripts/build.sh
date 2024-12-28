#!/bin/bash

# Retrieve domains labelled as suspicious from Gridinsoft website reputation
# checker.

readonly URL='https://gridinsoft.com/website-reputation-checker'

build() {
    # Append new domains
    # Some entries have '_' instead of '-' in the domain name
    curl -sS --retry 2 --retry-all-errors "$URL" \
        | grep -Po "online-virus-scanner/url/\K[[:alnum:].-_]+-[[:alnum:]-]+(?=\".*--suspicious\">)" \
        | mawk '{gsub(/_/, "-"); gsub(/-/, "."); print}' >> suspicious.txt

    # Compile list. See the list of transformations here:
    # https://github.com/AdguardTeam/HostlistCompiler
    # Note the hostlist compiler removes the previous comments and the Adblock
    # Plus header.
    printf "\n"
    hostlist-compiler -i suspicious.txt -o compiled.tmp

    # Remove comments
    sed -i '/!/d' compiled.tmp

    # Sort since the hostlist compiler does not sort the domains
    sort -u compiled.tmp -o compiled.tmp

    # Remove dead domains
    printf "\n"
    dead-domains-linter -a -i compiled.tmp

    # Deploy blocklist
    append_header
    cat compiled.tmp >> suspicious.txt
}

append_header() {
    cat << EOF > suspicious.txt
[Adblock Plus]
! Title: Gridinsoft Suspicious Domains Blocklsit
! Description: Suspicious domains scraped hourly from https://gridinsoft.com/website-reputation-checker and meant for https://github.com/jarelllama/Scam-Blocklist).
! Homepage: https://github.com/jarelllama/Gridinsoft-Blocklist
! License: https://github.com/jarelllama/Gridinsoft-Blocklist/blob/main/LICENSE
! Version: $(date -u +"%m.%d.%H%M%S.%Y")
! Expires: 1 hour
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

build