#!/usr/bin/env bash

# This step should install tools needed for all packages - OpenSSL and LDNS
echo "Updating tools"
brew update 1>/dev/null
echo "Installing tools"
brew install autoconf automake libtool pkg-config curl perl 1>/dev/null
