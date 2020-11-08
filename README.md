# Cert Sync

This project aims to synchronize certificates between a source and a
destination.

The example use case is :

- a Kubernetes cluster behind AWS ALB
- [`cert-manager`](https://cert-manager.io/docs/) that handles certificates on the cluster
- synchronize certificates created in cluster with the ALB (via ACM)

## Available sources

- Kubernetes

## Available destinations

- ACM (with possible ALB sync)

## Configuration

The program will seek the configuration file under `/app/config/config.yml` by default.
It can be modified via the env var `CONFIG_PATH`.

You can configure the log level via `RUST_LOG` : `info,kube=warn,hyper=error...`

The configuration file reference :

```yaml
aws:
  # Region, mandatory. The array form is due to the Rusoto library, but you cannot have several regions
  region:
    - eu-west-3
  # AWS credentials to use
  credentials:
    access_key: access_key
    secret_key: secret_key
  # Application Load Balancers ARNs to associate certificates with
  load_balancers:
    - arn:aws:elasticloadbalancing:eu-west-3:123456789012:loadbalancer/app/name/1234567890abcdef
    - arn:aws:elasticloadbalancing:eu-west-3:123456789012:loadbalancer/app/name-alt/1234567890abcdee
```

## Version upgrade

This project version bump is managed by `cargo-release`.

Install it with `cargo install cargo-release`.

## Notes

- Using RSA length different than 2048 will cause ACM to not list those
  certificates, and you won't be able to import them on ALB
