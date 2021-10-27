# Description

This project provide a program brute forcing the passphrase of a private key (EC/RSA).

:information_source: This project was created to allow me to learn the [Go](https://golang.org) technology.

# Usage

```text
Call syntax:
        pkcheck.exe {PASSPHRASE_DICTIONARY_FILE_PATH} {KEY_PEM_FILE_PATH} [--enable-derivation]
Call example:
        pkcheck.exe passphrases.txt pk-key-ec.txt
        pkcheck.exe passphrases.txt pk-key-ec.txt --enable-derivation
```

# Requirements

Go >= [1.17](https://golang.org/dl/)

# Release

[![Cross-Compile the program](https://github.com/righettod/pkcheck/actions/workflows/compile.yml/badge.svg?branch=main)](https://github.com/righettod/pkcheck/actions/workflows/compile.yml)

The binary files for Windows/Linux/Mac are compiled at each commit.

They are published as [release atefacts](https://github.com/righettod/pkcheck/releases/tag/latest).

# References

* [Go documentation](https://golang.org/doc/).
* [Go by Example](https://gobyexample.com/).
* [A Tour of Go](https://tour.golang.org/welcome/1).
* [Building Go Applications for Different Operating Systems and Architectures](https://www.digitalocean.com/community/tutorials/building-go-applications-for-different-operating-systems-and-architectures).