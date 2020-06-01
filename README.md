# ACM Certificate Sync

This project aims to synchronize your Kubernetes cluster certificates into AWS
ACM.

The example use case is :
- a Kubernetes cluster behind AWS ALB
- [`cert-manager`](https://cert-manager.io/docs/) that handles certificates on the cluster
- synchronize certificates created in cluster with the ALB (via ACM)