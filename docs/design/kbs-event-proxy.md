# KBS Event Proxy

## Overview

The KBS event proxy is a reverse proxy sidecar that runs alongside the KBS (Key Broker Service) container in the Trustee pod. It intercepts RCAR attestation HTTP traffic between nodes and KBS and emits Kubernetes events for attestation activity.

Without the proxy, attestation outcomes are only visible in KBS pod logs. The proxy surfaces these outcomes as first-class Kubernetes events on Machine and TrustedExecutionCluster resources.

## Problem

Trustee has no webhook, callback, or audit log for attestation outcomes. An administrator cannot answer "Did machine X attest successfully?" without reading KBS container logs. Kubernetes events provide a standard, queryable interface for this information.

## Architecture

The proxy runs as a sidecar container in the same pod as KBS. The Kubernetes Service routes external traffic to the proxy on port 8080. The proxy forwards all requests to KBS on localhost port 8081.

```
Nodes --> Service:8080 --> Proxy:8080 --(TLS)--> KBS:8081 (localhost)
                               |
                       inspects request/response
                               |
                       emits K8s events
```

Both hops use TLS. The proxy terminates external TLS from nodes, then connects to KBS via HTTPS on localhost. Both containers mount the same TLS secret volume.

### Why a reverse proxy

A metrics-based sidecar polls Prometheus counters and sees counter deltas, not individual events. The reverse proxy provides:

- Real-time event emission per attestation attempt
- Distinction between attestation failure (401) and resource policy denial (403)
- Session correlation across the three RCAR protocol steps
- Per-machine event attribution for resource requests

## RCAR Protocol

The RCAR (Remote CoCo Attestation and Retrieval) protocol has three HTTP steps. The proxy tracks sessions via the `kbs-session-id` cookie.

| Step | Endpoint | What the proxy observes |
|---|---|---|
| Auth | `POST /kbs/v0/auth` | TEE type from request body. Session cookie in response. |
| Attest | `POST /kbs/v0/attest` | 200 = attestation passed. Non-200 = failure. Session cookie identifies the session. |
| Resource | `GET /kbs/v0/resource/default/{id}/root` | Machine ID from URL path. 200 = key released. 403 = policy denied. 401 = rejected. |

### Session tracking

The proxy maintains an in-memory HashMap that maps session IDs (from the `kbs-session-id` cookie) to session metadata:

```
session_id -> SessionInfo { tee_type, created }
```

Sessions expire after 5 minutes (matching the KBS session timeout). The proxy cleans up expired sessions after each request.

## Events emitted

| Reason | Event type | Target resource | Trigger |
|---|---|---|---|
| `AttestationSucceeded` | Normal | Machine | Resource endpoint returns 200 for `default/{machine-id}/root` |
| `AttestationFailed` | Warning | TrustedExecutionCluster | Attest endpoint returns non-200 |
| `AttestationFailed` | Warning | Machine | Resource endpoint returns 401 for `default/{machine-id}/root` |
| `ResourcePolicyDenied` | Warning | Machine | Resource endpoint returns 403 for `default/{machine-id}/root` |

The proxy emits `AttestationFailed` on the TrustedExecutionCluster (not on a Machine) at the attest step because the RCAR protocol does not carry a machine identifier at that point. The session carries only the TEE type.

The resource step does carry the machine ID in the URL path. The proxy resolves machine IDs to Machine custom resources via the Kubernetes API.

## Deployment

### Pod spec changes

The operator modifies the Trustee pod spec in `operator/src/trustee.rs`:

1. KBS container listens on `127.0.0.1:8081` (internal only)
2. Proxy container listens on `0.0.0.0:8080` (exposed via Service)
3. Both containers mount the TLS secret volume
4. The pod uses the `trusted-cluster-operator` ServiceAccount for RBAC
5. The proxy receives `CONTROLLER_POD_NAME` via the downward API for event reporting

### Image resolution

The operator resolves the proxy image from the `RELATED_IMAGE_KBS_EVENT_PROXY` environment variable. If unset, it falls back to `{TEC_REGISTRY}/kbs-event-proxy:{COMPONENT_VERSION}`.

### RBAC

The proxy reuses the `trusted-cluster-operator` ServiceAccount. The ClusterRole includes:

- `events.k8s.io` API group: `create`, `patch` (for emitting events via the `events.k8s.io/v1` API)

The proxy also reads Machine and TrustedExecutionCluster resources to resolve object references for event targets. These permissions are already present in the operator's ClusterRole.

## TLS

The proxy accepts invalid TLS certificates when connecting to KBS on localhost. This is safe because the connection stays within the same pod on the loopback interface. The KBS TLS certificate contains the external hostname, not `127.0.0.1`, so strict validation would reject the connection.

The external-facing TLS termination uses the same certificate and key that KBS previously used directly. Nodes see no change in TLS behavior.

## Code structure

The proxy source is in `kbs-event-proxy/src/main.rs`, organized into six sections:

1. **Types and state**: CLI arguments, session info, proxy state with HTTP client, Kubernetes client, event recorder, and session map
2. **Request/response parsing**: Extract session IDs from Cookie and Set-Cookie headers, extract machine IDs from URL paths
3. **Kubernetes object lookups**: Resolve TrustedExecutionCluster and Machine custom resources to ObjectReferences for event targets
4. **RCAR attestation event handlers**: One handler per RCAR step (auth, attest, resource) that inspects the forwarded response and emits events
5. **Reverse proxy core**: Request forwarding, error responses, and the main handler that dispatches to event handlers based on URL path
6. **Entry point**: Client initialization, TLS configuration, and server startup

## Dependencies

The proxy reuses workspace dependencies:

- `axum` and `axum-server`: HTTP server and TLS termination (also used by register-server and attestation-key-register)
- `reqwest`: HTTP client for forwarding requests to KBS
- `kube` and `k8s-openapi`: Kubernetes API access and event recording
- `trusted-cluster-operator-lib`: Shared types (`Machine`, `record_event`, `get_trusted_execution_cluster`)

## Verification

After deployment, verify events with:

```bash
kubectl get events.events.k8s.io -n <namespace>
kubectl describe machine <machine-name>
```

A successful attestation produces an `AttestationSucceeded` event on the Machine resource. A failed attestation produces an `AttestationFailed` warning on the TrustedExecutionCluster resource.
