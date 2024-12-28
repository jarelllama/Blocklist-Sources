#!/bin/bash

# Retrieve suspicious domains from Gridinsoft website reputation checker.

# Some entries have '_' instead of '-' in the domain name
curl -sS --retry 2 --retry-all-errors \
    'https://gridinsoft.com/website-reputation-checker' \
    | grep -Po "online-virus-scanner/url/\K[[:alnum:].-_]+-[[:alnum:]-]+(?=\".*--suspicious\">)" \
    | mawk '{gsub(/_/, "-"); gsub(/-/, "."); print}' > suspicious.txt