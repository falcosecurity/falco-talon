---
title: Installation in k8s with Helm
description: How to install Falco Talon in Kubernetes with Helm
categories: [Examples]
tags: [test, sample, docs]
---

## Helm

The helm chart is available in the folder [`deployment/helm`](https://github.com/Issif/falco-talon/tree/main/deployment/helm).
Two config files are provided:
* `values.yaml` allows you to configure `Falcon Talon` and the deployment
* `rules.yaml` contains rules to set

```shell
cd deployment/helm/
helm install falco-talon . -n falco --create-namespace
```