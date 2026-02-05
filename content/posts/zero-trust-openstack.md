+++
title = "Bringing OpenStack to the Zero Trust era"
draft = true
description = "Rethinking Auth or OpenStack user in client applications"
date = "2026-03-01"
author = "Artem Goncharov"
+++

## Introduction

Historically, service-to-service communication within OpenStack has relied on
static, hardcoded credentials stored in plain-text configuration files. As the
industry shifts toward **Zero Trust Architecture (ZTA)**, these legacy methods
pose significant security risks. This paper proposes a transition to
cryptographically verified identities using the **SPIFFE** framework and **Open
Policy Agent (OPA)** to decouple authentication from authorization, eliminate
static secrets, and streamline policy management through a hybrid model that
preserves end-user context. Moreover, customers also demand isolating their data
even from the cloud operators.

---

## I. Current State and Limitations

The standard OpenStack authentication flow requires services to maintain
hardcoded credentials (service users) to communicate with Keystone for token
validation. This creates a "Secret Zero" problem where the compromise of a
single configuration file allows an attacker to impersonate an entire service
and necessitates complex procedures for credential rotation.

```kroki {_type=d2}
shape: sequence_diagram
client: |md
  # client
|
service_a: |md
  # service A
  contains hardcoded credentials to call keystone
|
service_b: |md
  # service B
  contains hardcoded credentials to call keystone
|
keystone: |md
  # Keystone
|
pdp: |md
  # Oslo.Policy
  or OPA
|
service_a <-> keystone: auth itself (token_a1)
service_a <-> keystone: auth for service_b (token_a2)
service_b <-> keystone: auth itself (token_b)

client <-> keystone: authenticate with credentials (token_c)

client -> service_a: api request (token_c)
service_a -> keystone: verify token (token_a1 + token_c)
keystone -> service_a: token roles
service_a -> pdp: verify authz
pdp -> service_a: allow/deny
service_a -> service_b: subaction (token_a2 + token_c)
service_b -> keystone: validate token_a2 and token_c
keystone -> service_b: tokens information
service_b -> pdp: verify authz
pdp -> service_b: allow/deny
service_b -> service_a: response
service_a -> client: result
```

While mTLS is currently supported, its implementation is cumbersome. It requires
Keystone to be deployed behind a web server or proxy that manages TLS
termination and maps certificates to specific user parameters limiting
infrastructure flexibility.

---

## II. Proposed Zero Trust Architecture

The proposed architecture adopts a Hybrid Token-SVID approach. It utilizes
**[SPIFFE](spiffe.io)** (Secure Production Identity Framework for Everyone) for
workload identity and service-to-service communication (Transport Layer) while
retaining Keystone Tokens (Fernet/JWT) for end-user context (Application Layer).

### Key Architectural Shifts:

- **Identity Verification (mTLS)**: Workload Identity is delegated to SPIFFE
  using X.509 SVIDs (SPIFFE Verifiable Identity Documents). This
  cryptographically proves "Service A" is actually "Service A" via hardware
  anchors (TPM).

- **Preserving User Context**: By keeping the Keystone Token in the request
  header, the receiving service (e.g., Cinder) still understands the user
  context. This allows the service to know exactly which user and project the
  request is on behalf of, preventing unauthorized resource access even if the
  service identity is valid.

- **Decoupled Authorization**: OPA acts as the Policy Decision Point (PDP). It
  receives the service SVID info and the User Token, then evaluates logic
  independently of service code.

```kroki {_type=d2}
shape: sequence_diagram
client: |md
  # client
|
service_a: |md
  # service A
|
service_b: |md
  # service B
|
opa: |md
  # Open Policy Agent
|
keystone: |md
  # Keystone
|
client -> keystone: authenticates
keystone -> client: returns user token
client -> service_a: API request (User Token)
service_a -> opa: verify authz (passes SVID_A + User Token)
opa -> keystone: validate SVID access & fetch roles
keystone -> opa: granted roles / scope
opa -> service_a: allow/deny
service_a -> service_b: api in user context (x.509 + User token)
service_b -> service_b: verifies service_a SVID
service_b -> opa: verify authz (SVID_B + User token)
opa -> keystone: validate SVID access & fetch roles
keystone -> opa: granted roles / scope
opa -> service_b: allow/deny
service_b -> service_a: response
service_a -> client: response
```

Assuming every node in the cloud is registered in SPIFFE, a SVID workload
identifier must be granted to it (eventually binding to the process UID to
differentiate services in cases where one node runs multiple services). An
example SVID might look like `spiffe://cloud.trust.domain/service/nova/az_1`. On
the request-accepting side, services accept client certificates and validate
their for expiration and against the SPIFFE server's CA.

Moving authorization verification out of the service code to an external Open
Policy Agent (OPA) to simplify policy management was demonstrated during a
previous OpenStack summit.

There are many more credentials inside of the OpenStack service configuration
files. This document describes a general introduction of the mTLS infrastructure
allowing services to start working on reusing it to get rid of hardcoded
secrets.

---

## III. Implementation Areas

### 1. Request Authentication (Keystone Middleware)

Instead of relying on the standard `auth_token` middleware, a new middleware
will verify that the client certificate was issued by the trusted SPIFFE
Certificate Authority. In the proposed workflow, no communication with Keystone
is required to verify workload identity; it is only necessary to verify that the
certificate is trusted and not expired. This allows for the use of dedicated
authentication-aware proxies to improve performance.

By default OpenStack services use `keystonemiddleware.auth_token` to validate
client authentication information. The same is valid for the service to service
communication. The middleware uses service credentials, found in the
configuration file for that. In the proposed workflow no communication with the
Keystone is required in order to verify the identity of the other service.
Instead it should be verified that the certificate was issued by the trusted
(SPIFFE) certificate authority and is not expired. This can be achieved using
the new dedicated middleware. No credentials are necessary since only CA
certificate must be known, allowing for the use of the authentication-aware
proxies to improve performance.

Switch from fernet tokens to JWT allows services to extract all necessary
information for the token passed the end user without invoking Keystone. Only
token signature must be verified.

### 2. Request Authorization (oslo.policy & OPA Bundles)

With the proposed change in request authentication, no information about client
permissions is available directly to the service. Some services rely on scope
information received during token validation to construct database queries. This
behavior often limits policy customization, such as implementing a "global
reader" role (where either the user has an admin role and `project_id` is
ignored, or the `project_id` must be explicitly known).

In this scenario, OPA is responsible for communicating with Keystone to resolve
necessary authorization data. The use of SPIFFE also makes it possible for OPA
to invoke service APIs directly with its own SVID when the policy depends on
additional data. This eliminates the need for the neutron-db-proxy when
deploying the architecture as demonstrated during the OpenStack summit talk
introducing OPA.

`keystonemiddleware` recently added support for use of the oauth2 tokens which
is only partially useful, since external authentication is usually missing any
scope information. Adding scope information into the authentication information
requires external system to have the knowledge of the OpenStack resource and
tenant models. This is a very error prone. Decoupling authentication and
authorization from each other makes it very easy to add support for many more
authentication mechanisms.

```kroki {_type=d2}
client: Client
idp: |md
  # IdP
  Arbitrary IdP
|
service: Service
client -> idp: authenticate
client -> service: API with auth token
service -> idp: validate authn (hardcoded trust)
service -> keystone: validate authn (dynamic trust)
service <-> opa: evaluate authorization
opa -> keystone: check grants

```

Integrating OPA helps solve the "Global Reader" problem. OPA can return not only
an allow/deny decision but also instructions on whether the user can list
resources outside of the current project scope.

OPA support for data bundles can be used to mitigate network latency. Keystone
can prepare signed JSON bundles containing user roles that are pulled by or
pushed to individual OPA instances used by services. This significantly improves
performance, though it moves the system toward eventual consistency regarding
permissions by introducing a synchronization lag (seconds). A decision of
performance versus consistency can be done by each provider individually.

Current default deployment scenario relies on the Fernet tokens. This is
dictated by the need to have a control over the authentication or authorization
revocation. Whenever a token is revoked a record in the Keystone database is
created invalidating the token. The same also happens wherever certain
permissions are revoked from the user. Having OPA fetching current authorization
information directly from Keystone makes this unnecessary.

### 3. Service-to-Service Communication

Services leverage OpenStackSDK/Keystoneauth for communication with each other.
To ensure maximum security, keystoneauth should be extended to communicate
directly with the Spire agent over a Unix Domain Socket to fetch short-lived
certificates, rather than reading them from the file system where they could be
compromised. For the transitioning phase SPIRE agent can be configured to write
certificates to the file system.

```kroki {_type=d2}
cloud: OpenStack cloud {
    spiffe: {
      shape: image
      icon: https://spiffe.io/img/logos/spiffe/horizontal/color/spiffe-horizontal-color.png
    }
    srv_foo: Service Foo {
      app
      opa
    }
    srv_bar: Service Bar {
      app
      opa
    }

    srv_foo.app <-> spiffe: fetch svid via socket
    srv_foo.opa <-> spiffe: fetch svid via socket
    srv_bar.app <-> spiffe: fetch svid via socket
    srv_bar.opa <-> spiffe: fetch svid via socket
    srv_foo.app -> srv_bar.app: mTLS connection with user token header
}

```

### 4. Kubernetes Token Exchange

SPIFFE enables mTLS communication between services whether they run on a bare
metal, in the cloud, containers or Kubernetes. There might be, however, use
cases where it is not feasible or desired to roll out the SPIFFE infrastructure.
Introducing a new authentication method using Kubernetes Token Review allows
workloads running in Kubernetes to authenticate to OpenStack using service
account tokens without hardcoding credentials. It can be used by the OpenStack
control plane running in Kubernetes and by cloud users to authenticate with the
cloud from their clusters.

```kroki {_type=d2}
client: Human
kubernetes: Kubernetes {
  pod {
    app
  }
}
keystone: Keystone
service: Service

client -> keystone: register K8
client -> keystone: define SA to Keystone user mapping
kubernetes.pod.app <-> keystone: exchange SA token for Keystone token
kubernetes.pod.app <-> service: call api with regular Keystone token
```

The change requires 2 separate components to be extended:

- Add set of new endpoints in Keystone:
  - Register the kubernetes cluster (CA) inside the certain domain.
  - Define the mapping of the service account JWT to the keystone user.
  - Exchange the kubernetes JWT token to keystone token.
- Extend OpenStackSDK/keystoneauth with the new authentication method.

### 5. Keystone Service Accounts

In many of the cases shown above it is necessary to map external identity to the
Keystone user. This is primarily required since permission management in
OpenStack requires a direct assignment between an actor and a target.

The concept of the user in Keystone allows certain flexibility. On the one hand,
a typical user is expected to have a password. Certain security options may
enforce the MFA, password rotation and additional protection mechanisms.
Moreover to perform actions as such user it is first necessary to get valid
authentication, what, in turn, requires a password (e.g., creating application
credentials or trust for the user account can be done only by the "user"
itself). On the other side there are federated users. Such users cannot have
credentials and can instead exchange externally obtain authentication for the
Keystone authentication. Last, but not least, there is a concept of the nonlocal
user in Keystone which is mostly left for the custom identity providers to use.

Current concept of the Keystone "user" is designed with the human in mind.
However, not every workload in the cloud can be related to the human. OpenStack
services that need to communicate with each other are not "humans", an
application running inside the Kubernetes pod is not a human, neither is the
cron job running Terraform is a human. As such, concept of service accounts,
based on the nonlocal users in Keystone, is being introduced. Those are still
"users" and have the `user_id`, but cannot have any direct credentials to login.
It is very similar to the OIDC federation, but machine accounts cannot have user
interaction usually required by the protocol. Instead a JWT token can be used to
obtain a Keystone token, or the mTLS in the case of SPIFFE.

Keystone API need to be extended with a new set of APIs allowing CRUD lifecycle
for the service accounts. Using the token restrictions and mappings rules it is
possible to restrict that a service account token obtained from a certain
workload is tied to a certain permissions set (set of roles on a fixed scope).
Such assignments can be even more fine-granular than simply the roles and e.g.,
grant an individual rule (as defined by the `oslo_policy`) like
`compute_server_list`. OPA enables much higher flexibility when defining the
policies. The policy can even check for only the service account identity (e.g.,
SVID) to grant access to certain operations for the service to service
communication instead of requiring explicit granting of the individual roles
through the Keystone (e.g., nova service account can do anything in cinder).

---

## IV. User Workload Identity

The most secure way for doing identifying workloads is to rely on the TPM. For
user VMs, SPIFFE can provide native identity, but we must address the Nova vTPM
technical debt.

```kroki {_type=d2}
shape: sequence_diagram
user
keystone
nova
vm
spiffe: {
  shape: image
  icon: https://spiffe.io/img/logos/spiffe/horizontal/color/spiffe-horizontal-color.png
}
user -> keystone: Register workload identity
user -> keystone: Grant permissions for the workload SVID
keystone -> spiffe: register expected workload
user -> nova: request new VM
nova -> vm: starts VM
nova -> vm: provides spiffe registration information
vm <-> spiffe: registers
vm -> user: a VM with keystone capable credentials (x.509 or JWT)
```

### 1. The Immobility Problem

To achieve production-ready Zero Trust for mobile workloads,
[vTPM Live Migration Specification](https://specs.openstack.org/openstack/nova-specs/specs/2025.1/approved/vtpm-live-migration.html)
must be finalized to allow the virtual TPM state to travel with the instance.

### 2. The Re-Attestation Flow

Until full migration is supported, a custom SPIRE Server Plugin that handles a
"placement check" can be used. When a VM moves and the TPM resets, the SPIRE
agent triggers re-attestation. The server plugin queries the Nova API to verify:
"Is VM-X authorized to be on Host-Y right now?"

### 3. Fallbacks (Less Secure)

In order to provide the most user friendly integration, all methods rely on the
vendordata service to not only to provide the secrets necessary for the node
attestation, but also to seamlessly provide the cloud-init snippets to install
and properly configure the SPIRE agent.

```config
[api]
# Enable the Dynamic provider
vendordata_providers = DynamicJSON
# Map a key name to your service URL
vendordata_dynamic_targets = "spiffe@http://identity-service.internal:8080/v1"

[vendordata_dynamic_auth]
# mTLS authentication
auth_type = spiffe
auth_url = http://keystone.internal:5000/v3
```

#### _Join-Tokens_

Nova can provide VM with a one-time join token through the vendordata. This is
vulnerable to interception but supports legacy migration.

#### _Cloud-API Attestation_

The vendordata service can provide the SPIRE agent with the signed data that is
verified by the SPIRE server via direct communication with the cloud API. This
method continues on where the
[abandoned implementation](https://github.com/zlabjp/spire-openstack-plugin/tree/poc-dynamic-json)
stopped and is used by many cloud competitors.

```kroki {_type=d2}
shape: sequence_diagram
user
nova
vm
spire_node_agent
vendordata
identity_service
spire_server: {
  shape: image
  icon: https://spiffe.io/img/logos/spiffe/horizontal/color/spiffe-horizontal-color.png
}

user -> nova: start VM
nova -> vm: start
vm -> spire_node_agent: invoke
spire_node_agent -> vendordata: fetch vendordata
vendordata -> identity_service: POST instance metadata
identity_service -> vendordata: sign instance metadata
vendordata -> spire_node_agent: signed metadata
spire_node_agent -> spire_server: authenticate node
spire_server -> nova: validate instance
nova -> spire_server: instance metadata
spire_server -> spire_node_agent: authenticates
spire_node_agent -> vm: finish authentication
vm -> user: ready for use

```

---

## V. Security Impact Analysis

### 1. Mitigation of Lateral Movement

- **Short-Lived SVIDs:** Replacing static secrets with short-lived,
  cryptographically verified SVIDs ensures that a compromised service provides
  no long-term credentials to an attacker.

- **Hardware Anchoring:** Identity is bound to hardware anchors (TPM),
  preventing credentials from being reused across different nodes.

### 2. Elimination of Revocation Lag

- **Real-time Authorization:** Delegating authorization to OPA removes total
  dependence on the traditional Fernet token lifecycle.

- **Immediate Updates:** OPA ensures that permission changes are reflected
  immediately via fresh data bundles or direct querying of the authoritative
  system.

### 3. Verified Delegation

The hybrid model prevents "Confused Deputy" attacks by ensuring a service only
acts if the mTLS handshake proves it is authorized and the token proves the
user's intent.

## VI. Performance Mitigation

- **Local Sidecar Execution:** OPA runs on the same node as the service (UDS
  communication).

- **Intelligent Caching:** Authorization decisions are cached locally.

- **Asynchronous Bundle Updates:** OPA pulls policy updates in the background to
  minimize API latency.

---

## VII. Conclusion

Transitioning OpenStack to a Zero Trust model addresses the critical
vulnerability of static secrets. By leveraging SPIFFE for transport identity and
OPA for centralized policy management, OpenStack can offer a modernized
framework that meets the demands of contemporary enterprise clouds.
