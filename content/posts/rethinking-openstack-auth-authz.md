+++
draft = true
title = "Rethinking of OpenStack Authentication and Authorization"
description = "Rethinking of OpenStack Authentication and Authorization"
date = "2025-02-12"
author = "Artem Goncharov"
+++


> **Draft**


# Rethinking of Authentication and Authorization support in OpenStack

For a long time I was dealing with diverse issues of authentication and
authorization in OpenStack. Lot of CSPs I was working with were raising
different, but at the same time similar complains towards missing or
inconvenient features. I decided to kick the process of rethinking what may or
should be improved in OpenStack to address diverse requirements.

Authentication and authorization are absolutely different things. At the same
time OpenStack (and honestly OAuth2 same) mixes them in the one step what
raises misunderstanding of their difference.

## Intro facts

### Authentication (AuthN)

Authentication verifies that the user is who he claims to be. Consider this
being an ID card of a human. Currently OpenStack requires user to authenticate
to Keystone and get the session token which other services are then accepting
granting user access to the resources.

Keystone currently supports following authentication methods (not complete
list):

- username + password. This may be extended to also require MFA.

- application credential with the secret. Those belong to the single user and
are tied to the certain authorization scope

- OIDC. Technically this is something most complains are being raised about. It
is not implemented natively by Keystone and as such has lots of limitations.


### Authorization (AuthZ)

Authorization controls what the authenticated user is allowed to do. In
OpenStack authorization is managed by few components. It is represented by an
authorization scope (being a project, a domain or a system) and roles a user is
being granted on the particular scope. This is being controlled by the Keystone
which is responsible of persisting this mapping. On the other side services
themselves are responsible for answering the question: what is the user with
the role able to do. There is no central management of such policies with those
being configured using yaml files on every host the service runs on.

When talking about authorization in OpenStack people usually think it is RBAC
(Role Based Access Control). This is wrong and in reality it is a hybrid or
RBAC and ABAC (Attribute Based Access Control). This is immediately clear once
a simple access policy rule is being analyzed: `rule:is_owner or role:manager`.
`is_owner` is something what verifies that attribute of the resource `user_id`
is the same that is being currently presented in the authentication
information.

Nowadays a concept of ReBAC (Relation Based Access Control) is becoming more
popular with solutions like OpenFGA based on Google Zanzibar. In that model
authorizations are being controlled by the authorization models with a triplet
actor-object-relation representing who is allowed to do what on which object.
OpenStack Keystone model is actually closer to the ReBAC than to the pure RBAC
because a single user (actor) is not simply having certain roles (can be mapped
to relations in ReBAC) but it has them in a certain scope (object). A role
assignment in the OpenStack is also a triplet actor-target-role.

A yet another complain I often hear about OpenStack is the lack of
fine-granular access control allowing to avoid falling into the role explosion
problem. At the same time management of the service policies is becoming much
more problematic.


## Problems

- OpenStack users (CSP customers) are not having possibility to establish user
federation (ldap, oidc) or similar without involving administrators.

- Federation using oidc is managed outside of Keystone itself (typically by
mod_auth_oidc module) what limits integration capabilities.

- it is not trivially possible to reuse single external IdP by different
customers while being themselves in a control of such integration.

- Modification of oidc federation requires restart of Keystone.

- Lack of an easy possibility to easily exchange JWT for an OpenStack token.

- Lack of fine-granular access control. Adding a new role dramatically
complicates policy management.

- Lack of possibility to integrate external authorization systems. This is
often necessary when OpenStack is just one offering in the service portfolio of
the CSP.

- Lack of service accounts concept. There is often a misunderstanding that
OpenStack user != human. Modeling service account as a user with a set of
application credentials can be used. However in a case of allowing Workflows to
consume cloud resources such accounts are very dynamic and usually cannot be
mapped to the application credential. In addition to that controlling
credentials of such account is more complex than it could be. Application
credentials can be only created by the user itself and not by other user with
administrative access.

Recently I have seen an idea of allowing OpenStack access with the OAuth2 on
the middleware side. On the first sight it looks logical. With the next loo few
weak points are popping up:

- covering complexity of OpenStack authorization model by the IdP is not
trivial. At the moment Keycloak does not support scope based role assignments.
As such it is not not trivial to ensure that OAuth token will contain properly
managed role assignments.

- service catalog fetching is not possible since Keystone does not itself use
middleware for authentication

- it is not possible for customers to control authentication and authorization
within their domain (not possible to configure own IdP or forbid access with
GitHub workflow JWT from a foreign repository).

Flipping the process around would be more logical. Here Keystone should become
an IdP itself and be able to issue a JWT. This could be then easily verified on
the middleware side by every OpenStack service establishing proper
centralization while at the same time providing full control to users. Further
this will allow implementing advanced features of authenticated workloads (i.e.
VM gets a direct API access token associated with certain permissions or
infrastructure based authentication).

## What could be done

### Federation rework

- allow user login with the oidc auth exchanging it for an OpenStack token. In
this scenario user initiates authentication with Keystone which serves as a
relying party and authenticates user with afterwards issuing an OpenStack token
to the user.

- allow exchange of JWT issued by the trusted IdP with the OpenStack token. A
simple use case here is a possibility for an GitHub workflow to access
OpenStack resources what is possible for the majority of cloud and service
providers

- Implement SCIM support so that customer is able in a self-service manner
synchronize domain users from an external IdP

### External authorization system

There is a series of specially designed authorization systems (OpenFGA,
OpenPolicyAgent, Permit, Authz, etc). 

#### OpenFGA 

It is possible to manage user-project-role assignments in an external system.
Using a system like OpenFGA in combination with a role assignment backend
plugin for Keystone allows a seamless integration of 2 worlds with management
of the assignments centrally in one place while at the same time keeping the
usual interface for users to manage their assignments using OpenStack API
(without a need to modify infrastructure deployment strategy (users can still
use OpenTofu with no change).

#### OpenPolicyAgent

Open Policy Agent is a CNCF project for managing authorizations in a typical
Policy As a Code approach while having possibility to provide data for a data
driven policy. It is a very established project supported by the majority of
services (Kubernetes, Ceph, ...). Idea of integration of OpenPolicyAgent with
OpenStack is [not
new](https://jaosorior.dev/2018/rewriting-openstack-policy-files-in-open-policy-agent-rego-language/).
On the one side implementing current policies (as done by oslo.policy) in Rego
(the official OPA language) is trivially possible even doing this
programmatically. OPA provides possibility to write test suites for the
policies. At the same time it is possible to treat policies in the typical
git-ops approach ensuring every policy change is being tested in the CI.
Policies can be managed centrally with the OPA instance (typically dedicated
for every service process to avoid expensive network requests) fetching
relevant policies automatically in the runtime not even requiring restart.
Strong point of OPA is a very small latency budget typically making
authorization decision in under 1 ms.

Thinking further on that it becomes possible to perform authorization decisions
already on the API GW (proxy) side reducing amount of invalid load on the
service process.

It depends on the deployment tool with CSP being able to optimize it for the
precise use case (i.e. using tools like Topaz or OPAL to automate data and
policy automation processes not supported by OPA natively).

## Changes

### OPA

Policy of every OpenStack service can be [automatically converted to the
OPA](https://github.com/gtema/oslo.policy.opa) and policy.yaml file delegating
the authorization decision on OpenPolicyAgent. All such policies should be
managed centrally in a dedicated git repository or similar platform. Further
dedicated grants can be implemented using ReBAC style with corresponding policy
changes and such assignments being fetched from system like OpenFGA or being
managed in a different way and provisioned into the OPA instance as required.
Overall this is achieved trivially and not a single line of OpenStack code need
to be changed. Only the deployment should be adapted.

In the long run perhaps managing all policies through the Keystone may be a
good thing centralizing different aspects of authentication and authorization
in OpenStack. OPA supports fetching of the policies and data from central
location as bundles and using keystone as such storage looks logical.


### Federation support

Majority of big cloud and service providers currently implement an exchange of
the OAuth2 (JWT) for a short living service token. One example is a GitHub
workflow where GitHub issues a JWT token and platforms like Vault, GCP, AWS,
Azure, etc allow to exchange it to the regular service token further supported
by all specific tools. This enables such workflow to access cloud resources.
Such approach will also keep all existing OpenStack tools working without a
change since they get an absolutely normal OpenStack token.

Other federation related issues in Keystone require certain changes:

- customers must be able to register own IdP. IdP may be globally enabled in
the installation and also some may be only bound to a single domain.

- customers must be able to manage configurations for the OAuth2/OIDC/JWT
integration specific to their domain.

- Exchange of OAuth2/JWT issued by external IdP to the Keystone token must be
implemented for every domain.

- Login user using external IdP (the RP mode of the OIDC flow) must be
implemented natively.

- SCIM protocol support must be implemented in Keystone to allow automatic user
data synchronization in combination with OIDC/OAuth user federation.


### New Auth flows

- OIDC (RP mode) - replace what mod_auth_oidc is doing now. Such auth request
may immediately include authorization request to avoid re-authorization
necessity. User sends auth request to a special URL in Keystone which
initializes OIDC auth and redirects user to the IdP. Once user authenticates at
the IdP it is being redirected to the localhost from where client passes
authorization code with to Keystone to complete the authorization code flow.
Client gets back the keystone token for the requested scope. This requires
having oauth/oidc client information in Keystone directly and every customer
must be able to connect their own IdPs

{{<mermaid>}}
sequenceDiagram

    Actor Human
    Human ->> Cli: Initiate auth
    Cli ->> Keystone: Fetch the OP auth url
    Keystone --> Keystone: Initialize authorization request
    Keystone ->> Cli: Returns authURL of the IdP with cli as redirect_uri
    Cli ->> User-Agent: Go to authURL
    User-Agent -->> IdP: opens authURL 
    IdP -->> User-Agent: Ask for consent
    Human -->> User-Agent: give consent
    User-Agent -->> IdP: Proceed
    IdP ->> Cli: callback with Authorization code
    Cli ->> Keystone: Exchange Authorization code for Keystone token
    Keystone ->> IdP: Exchange Authorization code for Access token
    IdP ->> Keystone: Return Access token
    Keystone ->> Cli: return Keystone token
    Cli ->> Human: Authorized


{{</mermaid>}}

- JWT. Client requests authorization providing JWT token issued by external
IdP. Keystone decodes the JWT, validates it with the issuer and after checking
authorization locally issues a regular token. Also here every customer must be
able to configure own rules and IdPs from which such requests are allowed. The
JWT subject may be a regular user (which is then considered in the same way as
an oidc federated user) or a workflow (similar to service account). Same as in
the OIDC flow token exchange request may contain scope information or be
hardcoded in the mapping.

{{<mermaid>}}

sequenceDiagram
    actor Requester
    Requester ->> Keystone: Authenticate with JWT
    activate Keystone
    Keystone -->> IdP: Validate JWT by issuer
    activate IdP
    IdP -->> Keystone: Valid
    deactivate IdP
    Keystone -->> Keystone: Issue Fernet token
    Keystone ->> Requester: Fernet Token
    deactivate Keystone

{{</mermaid>}}


### Keystone model change

There are many similarities between JWT and OIDC, but also differences (OIDC
flow will most likely contain client_id client_secret, while JWT will never has
this). Keeping that in mind and also having a peak at SAML configuration it
makes sense to separate them between dedicated tables.

At the CSP level there might be pre-configured IdPs that could be used by
domains. On the other side customers (domain) might need to manage their
dedicated IdPs. domain_id property of IdP should be optional so that it is
possible to implement IdP filtering based on customer domain_id or global ones.

Mappings should belong under the oidc/jwt configuration and be bound to the
domain.

{{<mermaid>}}

classDiagram
    class idp {
        +string id
        +Option~string~ domain_id
        +String name
    }

    class oidc {
        +string idp_id
        +option~string~ domain_id
        +string issuer
        +string client_id
        +string client_secret
        +option~string~ discovery_url
    }

    class jwt {
        +string idp_id
        +option~string~ domain_id
        +string issuer
        +string discovery_url
        +string jwks_url
    }

    class mapping {
        +string id
        +string name
        +string idp_id
        +string domain_id
        +option~string~ allowed_redirect_uri
        +option~string~ user_claim
        +option~string~ user_claim_json_pointer
        +option~string~ groups_claim
        +option~string~ bound_audiences
        +option~string~ bound_subject
        +option~string~ bound_claims
        +option~string~ bound_claim_types
        +option~string~ oidc_scopes
        +option~string~ claim_mappings
        +option~string~ token_user
        +option~string~ token_service_account
        +option~list~ token_roles
        +option~string~ token_project
    }

    class service_account {
        +string id
        +string user_id
        +string domain_id
        +string name
    }

    class user {
        +string id
        ...
    }

    oidc "1" --|> "1" idp: OIDC flow
    jwt "1" --|> "1" idp: JWT flow
    mapping "*" --|> "1" oidc: OIDC mapping
    mapping "*" --|> "1" jwt: JWT mapping
    service_account "1" ..> "1" user: mapped to the user
    mapping "*" .. "1" user: maps to regular user
    mapping "*" .. "1" service_account: maps to service accounts

{{</mermaid>}}
