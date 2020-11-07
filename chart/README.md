# Cert Sync Chart

This Chart installs `cert-sync` in your cluster.

## Configuration

Look at the `values.yaml` file for complete variables explanations.

## Kubernetes RBAC

This Chart requires access to Secrets cluster wide.
It will create the appropriate ServiceAccount, ClusterRole and
ClusterRoleBinding.
