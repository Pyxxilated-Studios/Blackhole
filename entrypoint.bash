#!/bin/bash

function server() {
    ./blackhole ${@}
}

function client() {
    bun index.js
}

command=$1
shift

case "${command}" in
    start)
        client &
        server ${@}
        ;;
    *)
        exec "${command} ${@}"
        ;;
esac
