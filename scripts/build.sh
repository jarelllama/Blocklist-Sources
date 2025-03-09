#!/bin/bash

# Retrieves domains from the various sources and builds the respective
# blocklist.

readonly DOMAIN_REGEX='(?:([\p{L}\p{N}][\p{L}\p{N}-]*[\p{L}\p{N}]|[\p{L}\p{N}])\.)+[\p{L}}][\p{L}\p{N}-]*[\p{L}\p{N}]'

readonly -a SOURCES=(
    chainabuse
    gridinsoft
    malwareurl
    tranco
)

main() {
    local source source_url
    for source in "${SOURCES[@]}"; do
        "source_${source}" || true

        cat source_results.tmp >> "${source}.txt"

        rm source_results.tmp

        # Remove carriage return characters, convert to lowercase, sort, and
        # remove duplicates.
        mawk '{ gsub("\r", ""); print tolower($0) }' "${source}.txt" \
            | sort -u -o "${source}.txt"
    done
}

source_chainabuse() {
    source_url='https://www.chainabuse.com/reports'

    # Scraping separate pages does not work
    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "domain\":\"(https?://)?\K${DOMAIN_REGEX}" > source_results.tmp
}

source_easydmarc() {
    source_url='https://easydmarc.com/tools/phishing-url'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "https://\K${DOMAIN_REGEX}(?=(/[^/]+)*</a></td><td><span class=\"eas-tag eas-tag--standard eas-tag--red\">SUSPICIOUS)" \
        > source_results.tmp
}

source_gridinsoft() {
    source_url='https://gridinsoft.com/website-reputation-checker'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | mawk '/<span>Suspicious/ { for(i=0; i<7; i++) getline; print }' \
        | grep -Po "$DOMAIN_REGEX" > source_results.tmp
}

source_malwareurl() {
    source_url='https://www.malwareurl.com'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "class=\"text-marked\">\K${DOMAIN_REGEX}(?=</span></li>)" \
        > source_results.tmp
}

source_tranco() {
    local source_url_1='https://tranco-list.eu/top-1m.csv.zip'
    local source_url_2='https://tranco-list.eu/top-1m-incl-subdomains.csv.zip'
    local max_attempts=3  # Retries twice
    local attempt=1

    while (( attempt <= max_attempts )); do
        # Download the toplists in parallel
        curl -sSL "$source_url_1" -o toplist1.zip &
        curl -sSL "$source_url_2" -o toplist2.zip

        {
            unzip -p toplist1.zip
            unzip -p toplist2.zip
        } | mawk -F ',' '{ print $2 }' > source_results.tmp

        rm toplist*.zip

        # Break out of loop if the toplists downloaded successffully.
        (( $(wc -l < source_results.tmp) == 2000000 )) && break

        (( attempt++ ))
    done
}

# Entry point

set -e

trap 'rm ./*.tmp temp 2> /dev/null || true' EXIT

main
