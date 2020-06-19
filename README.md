# tls-checker

## Description

`tls-checker` is used to verify that websites are serving on accepted TLS versions and not downgrading.

## Installation

TBD

## Usage

```sh
TBD
```

## Examples

Run the command like this:

```sh
bin/tls-checker --schemes https --hosts "www.truss.works" --log-level info --timeout 15m
```

There will be no output if the check succeeds. If there is an error output will appear like this:

```text
2020-06-19T10:28:41.199-0700    WARN    tls-checker/main.go:366 invalid request to url https://www.truss.works/health connected using TLS v1.1
```

When mutual TLS authentication is required this command can be used like this:

```sh
bin/tls-checker --schemes https --hosts "www.truss.works" --key "${KEY}" --cert "${CERT}" --ca "${CA}" --log-level info --timeout 15m
```

To ensure there's no issue with reading the KEY, CERT, and CA the values must be base64 encoded. One way to do this is
on the command line:

```sh
export KEY=$(echo $tls_key -q | base64 -i -)
export CERT=$(echo $tls_cert -q | base64 -i -)
export CA=$(echo $ca_cert -q | base64 -i -)
```
