#!/bin/bash
# Compile the program for Windows/Linux/Mac
allOS=(windows linux darwin)
rm -rf build 2>/dev/null
mkdir build 2>/dev/null
export GOARCH=amd64
for os in ${allOS[@]}; do
    export GOOS=$os
    bin_name="pkcheck-$GOOS-$GOARCH$GOEXE"
    go build -o build/$bin_name
    ls -l build/$bin_name
    file build/$bin_name
done
