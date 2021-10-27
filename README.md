# Description

This project provide a program brute forcing the passphrase of a private key (EC/RSA).

:information_source: This project was created to allow me to learn the [Go](https://golang.org) technology.

# Usage

```powershell
PS> pkcheck.exe {PASSPHRASE_DICTIONARY_FILE_PATH} {KEY_PEM_FILE_PATH}
PS> pkcheck.exe passphrases.txt pk-key-ec.txt
```

# Requirements

Go >= [1.17](https://golang.org/dl/)

# References

* [Go documentation](https://golang.org/doc/).
* [Go by Example](https://gobyexample.com/).
* [A Tour of Go](https://tour.golang.org/welcome/1).
* [Building Go Applications for Different Operating Systems and Architectures](https://www.digitalocean.com/community/tutorials/building-go-applications-for-different-operating-systems-and-architectures).