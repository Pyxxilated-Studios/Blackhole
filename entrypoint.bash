#!/bin/bash

function server() {
    ./blackhole
}

function client() {
    node index.js
}

case "$@" in
    start)
        server &
        client
        ;;
    *)
        exec "${@}"
        ;;
esac
