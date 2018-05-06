---
title: Workloads | Scanner
description: workloads of Scanner
menu:
  product_scanner_0.1.0:
    identifier: workloads-scanner
    name: Workloads
    parent: guides
    weight: 20
product_name: scanner
menu_name: product_scanner_0.1.0
section_menu_id: guides
---

> New to Scanner? Please start [here](/docs/concepts/README.md).

# Supported Workloads

Scanner supports the following types of Kubernetes workloads. Scanner rejects a workload to be created if any of it's images has vulnerability with severity level higher than the `--highest-acceptable-severity`(default is `Low`) of scanner. Supported levels are `Unknown`, `Negligible`, `Low`, `Medium`, `High`, `Critical`, `Defcon1`. Otherwise, the workload is free to be created.

> To go forward, we must need scanner to be run along with clair. You can find procedures for it [here](/docs/setup/install.md)

## Pods
To see how scanner behaves with a new Pod, create a Pod. You can find a full working demo in [examples folder](/docs/examples/workloads/pod.yaml).

## Deployments
To see how scanner behaves with a new Deployment, create a Deployment. You can find a full working demo in [examples folder](/docs/examples/workloads/deployment.yaml).

## ReplicaSets
To see how scanner behaves with a new ReplicaSet, create a ReplicaSet. You can find a full working demo in [examples folder](/docs/examples/workloads/replicaset.yaml).

## ReplicationControllers
To see how scanner behaves with a new ReplicationController, create a ReplicationController. You can find a full working demo in [examples folder](/docs/examples/workloads/replicationcontroller.yaml).

## DaemonSets
To see how scanner behaves with a new DaemonSet, create a DaemonSet. You can find a full working demo in [examples folder](/docs/examples/workloads/daemonset.yaml).

## Jobs
To see how scanner behaves with a new Job, create a Job. You can find a full working demo in [examples folder](/docs/examples/workloads/job.yaml).

## CronJobs
To see how scanner behaves with a new CronJob, create a CronJob. You can find a full working demo in [examples folder](/docs/examples/workloads/cronjob.yaml).

## StatefulSets
To see how scanner behaves with a new StatefulSet, create a StatefulSet. You can find a full working demo in [examples folder](/docs/examples/workloads/statefulset.yaml).

## Next Steps


