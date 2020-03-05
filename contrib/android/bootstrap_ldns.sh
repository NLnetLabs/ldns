#!/usr/bin/env bash

if ! git submodule update --init; then
    echo "Failed to init submodule"
    exit 1
fi

if [ -n $(command -v glibtool) ]; then
    if ! libtoolize -ci ; then
        echo "Failed to libtoolize (glibtool)"
        exit 1
    fi
elif [ -n $(command -v libtoolize) ]; then
    if ! libtoolize -ci ; then
        echo "Failed to libtoolize (libtoolize)"
        exit 1
    fi
elif [ -n $(command -v libtool) ]; then
    if ! libtoolize -ci ; then
        echo "Failed to libtoolize (libtool)"
        exit 1
    fi
fi

if ! wget -O config.guess 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'; then
    echo "Failed to download config.guess"
fi

if ! wget -O config.sub 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'; then
    echo "Failed to download config.sub"
fi

if ! autoreconf -fi ; then
    echo "Failed to autoreconf"
    exit 1
fi

exit 0
