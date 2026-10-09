# tangled-interceptor

A Tekton Triggers `ClusterInterceptor` that verifies [Tangled](https://tangled.org) webhook signatures.

Tangled signs the raw body as `X-Tangled-Signature-256: sha256=<hex hmac>`, the same scheme as
GitHub, but Tekton's built-in `github` interceptor only reads `X-Hub-Signature-256`, and CEL has
no HMAC function. This is a small static binary that does the check.

## Configuration

| Env | Default | |
|---|---|---|
| `WEBHOOK_SECRET_FILE` | required | File holding the webhook secret (surrounding whitespace is trimmed) |
| `SIGNATURE_HEADER` | `x-tangled-signature-256` | Header carrying `sha256=<hex hmac>`; makes it reusable for other GitHub-style senders |
| `LISTEN_ADDR` | `0.0.0.0:8080` | |

`POST /` is the interceptor endpoint, `GET /healthz` is for probes.

## Deploy

```yaml
apiVersion: triggers.tekton.dev/v1alpha1
kind: ClusterInterceptor
metadata:
  name: tangled
spec:
  clientConfig:
    service:
      name: tangled-interceptor
      namespace: tekton-pipelines
      port: 8080
```

Back it with a Deployment running the image, mounting the secret and setting `WEBHOOK_SECRET_FILE`,
then reference it from a Trigger:

```yaml
interceptors:
  - ref: { name: tangled, kind: ClusterInterceptor }
```

Failures return `continue: false` with `status.code` 3 (missing header, bad request) or 16 (bad signature).

## Develop

```sh
cargo test
docker build -t tangled-interceptor .
```
