+++
title = "Bringing OpenStack to the Zero Trust era"
draft = true
description = "Rethinking Auth or OpenStack user in client applications"
date = "2026-03-01"
author = "Artem Goncharov"
[build]
  list = 'never'
+++

## Introduction

Historically, service-to-service communication within OpenStack has relied on
static, hardcoded credentials stored in plain-text configuration files. As the
industry shifts toward **Zero Trust Architecture (ZTA)**, these legacy methods
pose significant security risks. This paper proposes a transition to
cryptographically verified identities using the **[SPIFFE](https://spiffe.io)**
framework and **Open Policy Agent (OPA)** to decouple authentication from
authorization, eliminate static secrets, and streamline policy management
through a hybrid model that preserves end-user context. Moreover, customers also
demand isolating their data even from the cloud operators.

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
**[SPIFFE](https://spiffe.io)** (Secure Production Identity Framework for
Everyone) for workload identity and service-to-service communication (Transport
Layer) while retaining Keystone Tokens (Fernet/JWT) for end-user context
(Application Layer).

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

### Service-to-Service Communication

Services leverage OpenStackSDK/Keystoneauth for communication with each other.
To ensure maximum security, keystoneauth should be extended to communicate
directly with the Spire agent over a Unix Domain Socket to fetch short-lived
certificates, rather than reading them from the file system where they could be
compromised. For the initial phase SPIRE agent can be configured to write
certificates to the file system. The final goal to reach here is that there are
no OpenStack service user passwords present in the configuration files. Only
mTLS based on SPIFFE is used instead. OpenStackSDK and keystoneauth libraries
already support mTLS, however it is used to authenticate to Keystone and fetch
its own token. Ideally they should not need to do this and instead only the
x.509 certificate should be used directly for communicating with the other
OpenStack service. This would most likely require changes in both mentioned
libraries, but it should be transparent to the services.

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

Services leverage OpenStackSDK/Keystoneauth for communication with each other.
To ensure maximum security, keystoneauth should be extended to communicate
directly with the Spire agent over a Unix Domain Socket to fetch short-lived
certificates, rather than reading them from the file system where they could be
compromised. For the transitioning phase SPIRE agent can be configured to write
certificates to the file system.

### Request Authentication (Keystone Middleware)

By default OpenStack services use `keystonemiddleware.auth_token` to validate
client authentication information (`X-Auth-Token`). The same is valid for the
service to service communication where additionally `X-Service-Token` is being
passed. The middleware uses service credentials, found in the configuration file
for calling Keystone for validating those tokens. There two different aspects of
the authentication middleware that need to be addressed independently Replacing
hardcoded credentials to communicate with Keystone for the token(s) validation.
In the early phase of the transition the middleware itself should use the SPIRE
managed x.509 certificate to communicate with Keystone. On the one hand, the
middleware already supports specifying the certificate files. The SPIRE agent
that is deployed on the host where the service is running can be configured to
write certificates to the file system. The middleware must ensure to watch for
the certificate file changes since this is rotated by the SPIRE agent
frequently. On the other hand, the middleware should be extended to communicate
directly with the SPIRE agent through the UNIX socket to rapidly improve the
overall platform security. Accepting x.509 certificates presented by the caller
in the case of service to service communication Services are intended to
communicate with each other directly with the x.509 certificates instead of
fetching and maintaining the Keystone tokens. Right now the middleware does not
support client certificates like e.g. `external_oauth2_token` middleware does.
It also requires the presence of the `X-Auth-Token`. The overall proposal does
not eliminate regular authentication tokens presented by end users, neither are
such tokens removed when services pass the initial user request context. Only
the `X-Auth-Token` is present: this is the regular end-user request and no
procedural change is expected. `X-Auth-Token` plus `X-Service-Token`: the
`X-Service-Token` is replaced with the x.509 certificate of the service.

There are few potential alternatives how such change can be implemented: Delayed
authentication: a new `spiffe` middleware must be created to verify the SPIFFE
x.509 certificate. When present it is validated and the
`HTTP_X_SERVICE_IDENTITY_STATUS`, `HTTP_X_SERVICE_USER_ID` and other parameters
are set correspondingly. The `auth_token` middleware should be placed
immediately after the `spiffe`. It must respect the potential result of the
x.509 certificate validation and treat it as a replacement for the
`X-Service-Token`. Since services can communicate with each other without the
user context (own `X-Auth-Token`) the middleware would need to set the
`HTTP_USER_*` headers instead of `HTTP_SERVICE_*` ones correspondingly.
`auth_token` middleware can be extended to additionally accept the x.509
certificate as `X-Service-Token`. This option leads to the bigger changes in the
middleware itself making the code even more complex, than it is right now.
However, this option will not require modification of the middleware pipelines.

Right now the `auth_token` middleware enforces certain roles to be present in
the `X-Service-Token` to prevent unauthorized operations. No additional service
roles validation is usually done within the authorization evaluation. Instead a
list of accepted SVID, signed by a trusted SPIFFE certificate authority, can be
configured so that the middleware relies on the service identity instead of the
dedicated roles assigned to it. This obsoletes the necessity for the roundtrip
to Keystone to validate service authentication and authorization. Switching from
fernet tokens to JWT allows services (middleware) to extract all necessary
information for the token passed by end user without invoking Keystone. Under
the assumption of using short-living tokens, only token signatures must be
verified. Otherwise a check for the revoked authentication must be performed
(for the JWT tokens this is the single cheap call to the database of `JTI` based
revocations which can be distributed across the platform through other channels
e.g., memcached). The request authorization validation is handled by the
relevant components described in the next chapter. In the case of authorization
changes, this removes the necessity of the authentication revocation, which
happens now dictating the need for the expensive token validation check.

### Request Authorization (oslo.policy & OPA Bundles)

Another major platform improvement can be achieved by separating validation of
the authentication from authorization. Currently, when a single user call
results in many individual requests to other involved services (like
provisioning a VM) user authentication and authorization are evaluated by
Keystone repeatedly without services needing that information. They are only
supposed to verify that the user authentication information is valid. SPIFFE
allows us to have a reliable cryptographically proven identity. Use of keystone
JWT token user authentication also enables very cheap authentication validation,
which can be passed from service to service without a need to re-evaluate it
every time (this addresses the need of the `X-Service-Token` which primary goal
is to allow validation of expired user authentication for the long running
operations). During the
[OpenStack Summit](https://www.youtube.com/watch?v=_B4Zsd8RG88&list=PLKqaoAnDyfgr91wN_12nwY321504Ctw1s&index=34)
authorization evaluation can be delegated to the specialized Open Policy Agent.
With the proposed change in request authentication, information about client
permissions may, and should, be unavailable to the service directly due to its
dynamic nature. In this scenario, OPA is responsible for communicating with
Keystone to obtain necessary authorization data on demand. The use of SPIFFE
also makes it possible for OPA to invoke service APIs directly with its own SVID
in the case when the policy needs additional data. This eliminates the need for
the neutron-db-proxy when deploying the architecture as demonstrated during the
mentioned talk and otherwise allows much higher flexibility in the policy
definitions.

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

Some services rely on authorization information received during token validation
to construct database queries. This behavior often limits policy customization,
such as implementing a "global reader" role (i.e. when either the user has an
admin role and `project_id` is ignored, or the `project_id` must be explicitly
present in the scope). Integrating OPA helps solve this problem when OPA returns
not only an allow/deny decision but also information on whether the user can
list resources outside of the current project scope. This is already used in the
Keystone re-implementation and showed to be a very effective and flexible
solution.

`keystonemiddleware` recently added support for user authentication with the
oauth2 tokens, is only partially useful, since any external authentication is by
design missing any scope information. Adding scope information into the
authentication information requires the external system to have the knowledge of
the OpenStack resource and tenant models. This is very tedious and error prone.
Decoupling authentication and authorization from each other makes it very easy
to add support for many more authentication mechanisms.

OPA support for data bundles can be used to mitigate network latency. Keystone
can prepare signed JSON bundles containing user roles that are pulled by or
pushed to individual OPA instances used by services. Keystone can also manage
the OPA policies for different services through the bundle mechanism building an
authorization control plane.

### Kubernetes Token Exchange

SPIFFE enables mTLS communication between services whether they run on bare
metal, in the cloud, containers or Kubernetes. There might be, however, use
cases where it is not feasible or desired to introduce the SPIFFE
infrastructure. Adding a new dedicated authentication method using Kubernetes
Token Review allows workloads running in Kubernetes to authenticate to OpenStack
using service account tokens without hardcoding credentials. It can be used by
the OpenStack control plane itself running in Kubernetes and by cloud users to
authenticate with the cloud from the clusters they own.

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
  - Register the kubernetes cluster (CA) inside a certain domain.
  - Define the mapping of the service account JWT to the keystone user.
  - Exchange the kubernetes JWT token to keystone token.
- Extend OpenStackSDK/keystoneauth with the new authentication method.

### Keystone Service Accounts

In many of the cases shown above it is necessary to map external identity to the
Keystone user. This is primarily required since permission management in
OpenStack requires a direct assignment between an actor and a target. The
concept of the user in Keystone allows certain flexibility. On the one hand, a
typical user is expected to have a password. Cloud security configurations may
enforce the MFA, password rotation and additional protection mechanisms.
Moreover to perform actions as a user it is first necessary to get valid
authentication, which, in turn, requires a password (e.g., creating application
credentials or trust for the user account can be done only by the "user"
itself). On the other side there are federated users. Such users cannot have
credentials and can instead exchange externally obtained authentication for the
Keystone authentication. Last, but not least, there is a concept of the nonlocal
user in Keystone which is mostly left for the custom identity providers to use.

The Keystone “user” is designed with the human in mind. However, not every
workload in the cloud can be related to humans. OpenStack services that need to
communicate with each other are not "humans", an application running inside the
Kubernetes pod is not a human, neither is the cron job running Terraform is a
human. As such, the concept of service accounts, based on the nonlocal users in
Keystone, is being introduced. Those are still "users" and have the `user_id`,
but cannot have any direct credentials to login. It is very similar to the OIDC
federation, but machine accounts cannot have user interaction usually required
by the protocol. Instead a JWT token can be used to exchange for a Keystone
token, or the mTLS in the case of SPIFFE.

Keystone API needs to be extended with a new set of APIs allowing CRUD lifecycle
for the service accounts. Using the token restrictions, introduced in the
Keystone reimplementation, and mappings rules it is possible to restrict that a
service account token obtained from a certain workload is tied to a certain
permissions set (set of roles on a fixed scope). Such assignments can be even
more fine-granular than simply the roles and e.g., grant an individual rule (as
defined by the `oslo_policy`) like `compute_server_list`. OPA enables much
higher flexibility when defining the policies. The policy can even check for
only the service account identity (e.g., SVID) to grant access to certain
operations for the service to service communication instead of requiring
explicit granting of the individual roles through the Keystone (e.g., Nova
service account can do any read operation in Keystone).

---

## IV. User Workload Identity

The most secure way for identifying workloads today is to rely on the TPM. For
user VMs, SPIFFE can provide native identity, but we must address the
[Nova vTPM technical debt](https://docs.openstack.org/nova/latest/admin/emulated-tpm.html#limitations).

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
“placement check” can be used. When a VM moves and the TPM resets, the SPIRE
agent triggers re-attestation. The server plugin queries the Nova API to verify:
“Is VM-X authorized to be on Host-Y right now?”

### 3. Fallbacks (Less Secure)

In order to provide the most user friendly integration, all methods rely on the
vendordata service to not only to provide the secrets necessary for the node
attestation, but also to seamlessly inject the cloud-init snippets for SPIRE
agent installation and configuration.

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

## V. Implementation steps

Implementing the outline approach is not going to be immediate and requires
careful coordination between services. In the core of the proposal there are
major dependencies on Keystone. Some of those features are already addressed in
the Keystone rewrite. As announced earlier most of them cannot be easily
implemented with the current Keystone architecture and require major rework
anyway. As such a step-wise approach is being proposed. Some of the steps
require code changes, some only deployment changes, some steps can be
parallelized since they do not necessarily depend on one team or service.

- Phase: Preparation
  - Keystone must implement mTLS authentication natively without requiring being
    deployed behind the reverse-proxy.
  - SPIFFE/SPIRE is deployed in the platform and nodes are registered
    correspondingly to be able to fetch SVID x.509 certificates.
  - Keystone must start accepting SVID x.509 certificates (as authentication
    method)
  - Keystone must add support for the service accounts.
- Phase: Remove passwords from `keystone_authtoken` middleware
  - Services replace credentials used by the `keystone_authtoken` middleware to
    SPIFFE certificate (either found on the file system or when the middleware
    is extended directly obtained from the agent).
- Phase: Prepare mTLS middleware
  - `spiffe` middleware must be implemented to accept client x.509 certificates.
  - `keystone_authtoken` must be extended to respect information eventually
    populated by the `spiffe` middleware.
  - Services modify middleware pipelines to include the `spiffe` middleware.
- Phase: Enable services to use mTLS communication
  - `spiffe` authentication method is added to the `openstacksdk` and
    `keystoneauth` to obtain the x.509 certificate from the agent socket.
  - Services replace authentication for cross-service communication to the
    `spiffe` type.
- Phase: Authorization separation preparation
  - OPA processes must be deployed as side cars for every service. It must
    authenticate itself at SPIFFE obtaining a valid SVID.
  - Keystone must be extended to let OPA query roles with its own SVID without
    an explicit authentication step.
  - `oslo_policy` policies are converted into the OPA Rego.
  - OPA policies must invoke Keystone for fetching current user scope roles if
    those are not available in the passed context.
- Phase: Authorization separation completion
  - Service policies are extended to allow returning additional information in
    combination with the allow/deny decision (e.g., whether the user is allowed
    to perform this operation in a different scope - `is_admin`)
  - Services must be updated to not to hardcode user authorization information
    in the code (i.e. `is_admin`) but instead obtain this information from the
    OPA decision.
- Phase: JWT tokens
  - A new mechanism of checking for the token revocation is introduced, either
    in Keystone directly or any alternative
  - Keystone switches to using JWT tokens
  - Authentication middleware (mostly `keystone_authtoken`) stops relying on the
    authorization information from Keystone. Scope information is obtained from
    the token or from the request headers (what `keystoneauth` assumes for the
    tokenless authentication). For JWT tokens this information is obtained from
    the token and not from Keystone.
  - Authentication middleware validates authentication for: CA chain trust,
    expiration, revocation.

Management of the SPIFFE itself is not in the focus of the OpenStack deployment.
However, it may be decided to enable close integration, e.g., via Keystone that
would be used by the users for the workload identity.

Work on Kubernetes Token Review is not considered here and is going to be
implemented independently from the above plan, however there are certain
dependencies on the features outlined there.

Workload identity implementation was not considered in the above plan. There are
too many dependencies on the features that need to be implemented above, but
some work can be also done in parallel. It should be properly planned together
with the Nova team in a separate, but relate, plan.

---

## VI. Security Impact Analysis

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

## VII. Performance Mitigation

- **Local Sidecar Execution:** OPA runs on the same node as the service.

- **Intelligent Caching:** Authorization decisions are cached locally.

- **Asynchronous Bundle Updates:** OPA pulls policy updates in the background to
  minimize API latency.

---

## VIII. Conclusion

Transitioning OpenStack to a Zero Trust model addresses the critical
vulnerability of static secrets. By leveraging SPIFFE for transport identity and
OPA for centralized policy management, OpenStack can offer a modernized
framework that meets the demands of contemporary enterprise clouds.
