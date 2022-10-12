#!/bin/bash

function server() {
    ./blackhole ${@}
}

function client() {
    node index.js
}

case "$1" in
    start)
        client &
        server ${@}
        ;;
    *)
        command=$1
        shift
        exec "${command} ${@}"
        ;;
esac
