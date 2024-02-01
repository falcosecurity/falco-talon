---
title: List of Actionners
weight: 5
description: >
  Available actionners
---

The `required fields` are the field elements that must be present in your Falco events to allow the actionner to do its work.

## `kubernetes:terminate`

* Description: **Terminate pod**
* Continue: `false`
* Parameters:
  * `grace_period_seconds`: The duration in seconds before the pod should be deleted. The value zero indicates delete immediately.
  * `ignore_daemonsets`: If true, the pods which belong to a Daemonset are not terminated.
  * `ignore_statefulsets`: If true, the pods which belong to a Statefulset are not terminated.
  * `min_healthy_replicas`: Minimum number of healthy pods to allow the termination, can be an absolute or % value (the value must be a quoted string).
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`

## `kubernetes:labelize`

* Description: **Add, modify or delete labels of pod**
* Continue: `true`
* Parameters: 
  * `labels`: key:value map of labels to add/modify/delete (empty value means label deletion)
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`

## `kubernetes:networkpolicy`

* Description: **Create, update a network policy to block all egress traffic for pod**
* Continue: `true`
* Parameters:
  * `allow`: list of CIDR to allow anyway (eg: private subnets)
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`

## `kubernetes:exec`

* Description: **Exec a command in a pod**
* Continue: `true`
* Parameters:
  * `shell`: SHELL used to run the command (default: `/bin/sh`)
  * `command` Command to run
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`

## `kubernetes:script`

* Description: **Run a script in a pod**
* Continue: `true`
* Parameters:
  * `shell`: SHELL used to run the script (default; `/bin/sh`)
  * `script`: Script to run (use `|` to use multilines) (can't be used at the same time than `file`)
  * `file`: Shell script file (can't be used at the same time than `script`)
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`

## `kubernetes:log`

* Description: **Get logs from a pod**
* Continue: `true`
* Parameters:
  * `tail_lines`: The number of lines from the end of the logs to show (default: `1000`)
* Required fields:
  * `k8s.pod.name`
  * `k8s.ns.name`
