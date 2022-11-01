#!/bin/bash

function server() {
    ./blackhole ${@}
}

function client() {
    deno run --allow-net --allow-env --allow-read index.js
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
