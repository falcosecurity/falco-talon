---
title: Usage
description: How to use Falco Talon
categories: [Examples, Placeholders]
tags: [test, docs]
weight: 3
---

```shell
$ falco-talon --help

Falco Talon is a Response Engine for managing threats in Kubernetes 
It enhances the solutions proposed by Falco community with a dedicated, 
no-code solution. With easy rules, you can perform actions over compromised pods

Usage:
  falco-talon [command]

Available Commands:
  check       Check Falco Talon Rules file
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  server      Start Falco Talon
  version     Print version of Falco Talon.

Flags:
  -c, --config string       Falco Talon Config File (default "/etc/falco-talon/config.yaml")
  -h, --help                help for falco-talon
  -r, --rules stringArray   Falco Talon Rules File (default [/etc/falco-talon/rules.yaml])

Use "falco-talon [command] --help" for more information about a command.
```

```shell
$ falco-talon server --help

Start Falco Talon

Usage:
  falco-talon server [flags]

Flags:
  -h, --help   help for server

Global Flags:
  -c, --config string       Falco Talon Config File (default "/etc/falco-talon/config.yaml")
  -r, --rules stringArray   Falco Talon Rules File (default [/etc/falco-talon/rules.yaml])
```

```shell
$ falco-talon check --help

Check Falco Talon Rules file

Usage:
  falco-talon check [flags]

Flags:
  -h, --help   help for check

Global Flags:
  -c, --config string       Falco Talon Config File (default "/etc/falco-talon/config.yaml")
  -r, --rules stringArray   Falco Talon Rules File (default [/etc/falco-talon/rules.yaml])
```