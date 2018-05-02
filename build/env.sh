#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
ethdir="$workspace/src/github.com/ethereum"
if [ ! -L "$ethdir/go-ethereum" ]; then
    mkdir -p "$ethdir"
    cd "$ethdir"
    cp -r "$PWD/go-ethereum"  go-ethereum
   # ln -s ../../../../../. go-ethereum
    cd "$root"
fi
bigfloat="$workspace/src/github.com/bigfloat"
if [ ! -L "$bigfloat/bigfloat" ]; then
    cp -r "$PWD/bigfloat" "$workspace/src/github.com/"

fi


# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$ethdir/go-ethereum"
PWD="$ethdir/go-ethereum"

# Launch the arguments with the configured environment.
exec "$@"
