# Isolated scan jobs

Apply `scanner-rbac.yaml`, create the `exposurescopex-results` ReadWriteMany PVC, and create an `exposurescopex-runtime` Secret containing the backend, Redis, and scanner configuration used by the worker image. Run the Celery controller under the `exposurescopex-worker` service account with `SCAN_EXECUTOR=kubernetes`.

The controller can create, inspect, and cancel Jobs only in the `exposurescopex` namespace. Scan pods have no Kubernetes token, deny ingress, use a read-only root filesystem, and receive bounded temporary volumes. Keep `SCAN_JOB_ALLOW_NET_RAW=false` unless the approved scan profile requires raw sockets.

Use an immutable digest for `SCAN_JOB_IMAGE` in production. Store API keys in the Secret rather than the ConfigMap and scope outbound network access at the cluster firewall or CNI layer to approved assessment targets and configured scanner services.
