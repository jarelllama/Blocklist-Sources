#!/bin/bash

# Retrieves domains from the various sources and builds the respective
# blocklist.

readonly DOMAIN_REGEX='[[:alnum:]][[:alnum:].-]*[[:alnum:]]\.[[:alnum:]-]*[a-z]{2,}[[:alnum:]-]*'

readonly -a SOURCES=(
    chainabuse
    gridinsoft
    malwareurl
)

main() {
    local source
    for source in "${SOURCES[@]}"; do
        "source_${source}" >> "${source}.txt" || true
        build
    done
}

source_chainabuse() {
    source_url='https://www.chainabuse.com/reports'

    # Scraping separate pages does not work
    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "domain\":\"https?://\K${DOMAIN_REGEX}"
}

source_easydmarc() {
    source_url='https://easydmarc.com/tools/phishing-url'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "https://\K${DOMAIN_REGEX}(?=(/[^/]+)*</a></td><td><span class=\"eas-tag eas-tag--standard eas-tag--red\">SUSPICIOUS)"
}

source_gridinsoft() {
    source_url='https://gridinsoft.com/website-reputation-checker'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | mawk '/<span>Suspicious/ { for(i=0; i<7; i++) getline; print }' \
        | grep -Po "$DOMAIN_REGEX"
}

source_malwareurl() {
    source_url='https://www.malwareurl.com'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "class=\"text-marked\">\K${DOMAIN_REGEX}(?=</span></li>)"
}

# Format the blocklist.
build() {
    # Compile list. See the list of transformations here:
    # https://github.com/AdguardTeam/HostlistCompiler
    # Note the hostlist compiler removes the previous comments and the Adblock
    # Plus header.
    printf "\n"
    hostlist-compiler -i "${source}.txt" -o compiled.tmp

    # Sort as the hostlist compiler does not sort
    sort -u "${source}.txt" -o "${source}.txt"

    # Remove comments
    sed -i '/!/d' compiled.tmp

    # Append header
    cat << EOF > "${source}.txt"
[Adblock Plus]
! Title: Blocklist to be used as a source for https://github.com/jarelllama/Scam-Blocklist
! Description: Blocklist to be used as a source for https://github.com/jarelllama/Scam-Blocklist.
! Homepage: https://github.com/jarelllama/Blocklist-Sources
! License: https://github.com/jarelllama/Blocklist-Sources/blob/main/LICENSE
! Version: $(date -u +"%m.%d.%H%M%S.%Y")
! Expires: 10 minutes
! Last modified: $(date -u)
! Syntax: Adblock Plus
! Number of entries: $(wc -l < compiled.tmp)
!
EOF

    cat compiled.tmp >> "${source}.txt"
}

# Entry point

set -e

trap 'rm ./*.tmp temp 2> /dev/null || true' EXIT

# Install AdGuard's Dead Domains Linter
if ! command -v dead-domains-linter &> /dev/null; then
    npm install -g @adguard/dead-domains-linter > /dev/null
fi

# Install AdGuard's Hostlist Compiler
if ! command -v hostlist-compiler &> /dev/null; then
    npm install -g @adguard/hostlist-compiler > /dev/null
fi

main
