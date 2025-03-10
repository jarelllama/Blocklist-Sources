#!/bin/bash

# Retrieve domains from the various sources.

readonly DOMAIN_REGEX='(?:([\p{L}\p{N}][\p{L}\p{N}-]*[\p{L}\p{N}]|[\p{L}\p{N}])\.)+[\p{L}}][\p{L}\p{N}-]*[\p{L}\p{N}]'

readonly -a SOURCES=(
    chainabuse
    franceverif
    gridinsoft
    malwareurl
    scamscavenger
    tranco
)

main() {
    local source source_url
    for source in "${SOURCES[@]}"; do
        "source_${source}" || true

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
        | grep -Po "domain\":\"(https?://)?\K${DOMAIN_REGEX}" \
        >> "${source}.txt"
}

source_franceverif() {
    source_url='https://franceverif.fr/fr/verifier-site-web'

    curl -sSL --retry 2 --retry-all-errors "$source_url" |
        grep -Po '(?<=dangerous).*?(?=recently)' | grep -Po "$DOMAIN_REGEX" \
        >> "${source}.txt"
}

source_gridinsoft() {
    source_url='https://gridinsoft.com/website-reputation-checker'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | mawk '/<span>Suspicious/ { for(i=0; i<7; i++) getline; print }' \
        | grep -Po "$DOMAIN_REGEX" >> "${source}.txt"
}

source_malwareurl() {
    source_url='https://www.malwareurl.com'

    curl -sSL --retry 2 --retry-all-errors "$source_url" \
        | grep -Po "class=\"text-marked\">\K${DOMAIN_REGEX}(?=</span></li>)" \
        >> "${source}.txt"
}

source_scamscavenger() {
    source_url='https://scamscavenger.tech/projectstatistics'

    # Retry 5 times as the site often has trouble loading
    curl -sSL --retry 5 --retry-all-errors "$source_url" | mawk '
        /Today scam/ {
            block = 1;
            next
        }
        /Number added by days/ {
            block = 0
        }
        block
        ' | grep -Po "<h4 class=\"trial-rating\">\K${DOMAIN_REGEX}" \
        >> "${source}.txt"
}

source_tranco() {
    local source_url='https://tranco-list.eu/top-1m-incl-subdomains.csv.zip'
    local max_attempts=3  # Retries twice
    local attempt=1

    while (( attempt <= max_attempts )); do
        curl -sSL --retry 2 --retry-all-errors "$source_url" -o temp
        unzip -p temp | mawk -F ',' '{ print $2 }' > "${source}.txt"

        # Break out of loop if download was successfully
        (( $(wc -l < "${source}.txt") == 1000000 )) && break

        (( attempt++ ))
    done
}

# Entry point

set -e

trap 'rm ./*.tmp temp 2> /dev/null || true' EXIT

main
