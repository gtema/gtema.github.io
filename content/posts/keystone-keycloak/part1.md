+++
title = "Configuring Keystone-Keycloak federation - part 1"
description = "Enabling OpenIDConnect federation between Keystone as Service Provider and Keycloak as Identity provider with ephemeral users"
date = "2024-02-10"
author = "Artem Goncharov"
+++

In this series of articles we are going to discuss how to configure Keystone
with an external Identity provider (federation) based on the Keycloak with
OpenIDConnect and multiple domain support. Since there are currently issues
doing so effectively the information will come synchronized with addressing of
the the mentioned challenges. This part is focused on making it possible to
have an external Identity provider and map remotely managed users to multiple
local domains and projects.

[official
documentation](https://docs.openstack.org/keystone/latest/admin/federation/configure_federation.html)
provides information required for Keystone configuration and can be used for
the reference, but it is not sufficient for the context of this article.


# Keystone in few words

Keystone is an Identity provider service in OpenStack. In it's current version
it serves few major purposes:

- manage identity resources (users, domain, projects, catalogs)

- authenticate/authorize users granting them session API token

- verify user presented token (this capability is normally used by other
services to verify the user is valid and can do what he tries to do)

By default Keystone is keeping user data locally and thus builds itself an
identity authority. But it can also be combined with external identity
authorities in which case it is named as "Federation". There are few built-in 
protocols that Keystone supports to delegate user data authority to the
third party:

- LDAP

- OpenIDConnect

- Saml2

In the scope of this series we are going to look at how to configure Keystone to 
delegate user management to the Keycloak based on the OpenIDConnect protocol.

## Federation Issues

The only possibility for building up a federation in Keystone was by
registering an external identity provider in a certain local domain. This has a
logical consequence that all users from the remote identity server are mapped
to the domain where the identity provider was registered. It works pretty well
when OpenStack installation is relatively small or being used as a private
cloud with no real segregation based on domains. For the wider use case,
however, this is not appropriate anymore. Of course it is possible to register
multiple identity providers in all required domains, but since Keystone on its
own delegates OpenIDConnect protocol work to additional plugins of the web
server (mod_oidc for Apache is one of those possibilities) it also means that
configuration for those plugins must be also repeated X times, not forgetting
the need to create also multiple OpenID clients in the Identity provider itself
to enable such mapping. 

Next issue is related with the user authorization: which resources does the
user have access to and what are the privileges. In OpenStack this is
represented by roles granted to the user on a certain resources (project or
domain). This mapping is stored statically in OpenStack as CRUD based
resources. Now when we want to manage users in one system but their privileges
in another system this leads absolutely logically to a nightmare.

## Why federate at all?

If you ask this question then most likely you do not need to have a federation
and you can just stretch the Keystone across multiple regions. Here we try to
provide some more information when having an external Identity provider is a
non-avoidable fact. 

Security becomes more and more complex day by day. Simple 2-factor protection
is not considered safe anymore and additional device based account protections
are appearing (passkeys, hardware tokens, etc). Keystone is currently not able
to deal with such new possibilities. On another side there is often need to
reuse users in different applications (aside from OpenStack). This is actually
what OAuth and OpenIDConnect were created for separating the Identity providers
from Service providers. Keystone alone does not currently serves good as a good
Identity provider for applications outside of the OpenStack.

It would be technically possible to extend OpenStack services (Nova, Cinder,
Glance, etc) to work directly with an external Identity provider but would
require quite a big effort. It is much easier to make Keystone itself a Service
provider that deals with the user authorization (issue authorization token that
other OpenStack services accepts).

# Improving federation capabilities of Keystone

Now that we understand why federation makes sense and which issues are there
currently we know what need to be improved.

As described in the previous chapter first problem that need to be solved is a
need to be able to map users from an external Identity provider into different
domains in OpenStack.

Keystone currently supports 2 different types of users: `local` and
`ephemeral`. A `local` user, as the name suggests, is a user that Keystone has
ownership of and is responsible for. An `ephemeral` one is a user that external
entity is owning, but Keystone must be aware of to grant OpenStack use.
Federation is relying on the `ephemeral` users. In order to let Keystone
recognise such external user it need to map it to a local "ephemeral" entity to
be able to grant roles, projects access, etc. Such users are not even stored in
the same DB table in Keystone where local users are stored.

Since a few years there was a solution proposed for the problem, but it was
unfortunately postponed for the next release (due to the timing constraints)
and later missed completely. Few companies interested in seeing the problem
finally solved came together and agreed on a collaboration to finally see the
improvements. With [this
change](https://review.opendev.org/c/openstack/keystone/+/739966) improvement
of an ephemeral users handling has been finally merged and it became possible
to map users into different domains. One important thing here is that the
Domain must be existing by the time the federated users tries to login,
otherwise the authentication fails with no reasonable information available to
the user.

So let us quickly have a look at the steps and sample configuration of the
Keycloak, Keystone and the Apache web server in front of Keystone since we are
going to rely on the mod_oidc module for taking over the OpenIDConnect work.

# OpenIDConnect client (Keycloak)

Since it is desired to have users managed inside of Keycloak being available
inside of Keystone it is necessary to create a client. There are lot of
[existing materials](https://openid.net/developers/specs/) describing how the
OpenIDConnect works. [A High level
description](https://openid.net/developers/how-connect-works/) giving following
description to the "Client":

> A client is a piece of software that requests tokens either for
> authenticating a user or for accessing a resource (also often called a
> relying party or RP). A client must be registered with the OP (OpenID
> Provider). Clients can be web applications, native mobile and desktop
> applications, etc. 

In Keycloak a "Client" is a CRUD resource representing the application (on our
case Keystone) that would be able to access user data. The "Client" has certain
configuration options that influence communication between both sides as well
as describes which specific OpenIDConnect workflows are supported
(Authorization Code, Implicit, Resource owner password credentials, Client
credentials, Device authorization, etc). With this amount of things that can be
misconfigured is relatively endless. Therefore we start with the most basic
configuration allowing us to see the Keycloak user being able to get the
Keystone token to further talk to other OpenStack services.

Keycloak has a decent GUI, but it is hard to describe in text which of 10000
check-boxes need to be checked. Actually there is nothing very specific on the
client for the moment except following properties:

- protocol: "openid-connect"

- client authentication: "on"

- authentication flow: standard, implicit (allowing more is not harming, but is
not necessary as of now)

- Valid redirect URI. This is a tricky one to describe since it depends on how
Keystone is deployed. Since here we deploy both Keystone and Keycloak on the
localhost we use: 
  - http://localhost:5000/v3/auth/OS-FEDERATION/websso/openid
  - http://localhost:5000/identity/v3/auth/OS-FEDERATION/identity_providers/sso/protocols/openid/websso

Redirect URI is a safety measure to allow Keycloak redirect user back to the
Keystone and not let the flow being high-jacked by some other application.

Once the client is created it is necessary to describe which data Keycloak is
going to expose to the client (Keystone) about the user. Our main target for
now is to expose user name and unique ID (ID of the Keystone). Another
crucially important user attribute is the domain name (or ID) that the user
must be assigned into in the Keystone. This is actually why all of the
improvements are required. Such configuration in Keycloak is being described by
a "Client scope". Keycloak comes with default client scopes being
pre-configured for the OpenIDConnect and can be extended with the information
we are going to need. For the re-usability and configuration sanity it is,
however, suggested to create a dedicated client scope that will not configure
all the extensions and applied only to those clients, that really need them.

![Client Scope](../images/keycloak_client_scope.png)

As a next step we are going to create mappers that add defined user attributes
into the exposed information. For this we switch to the mappers tab and add a
new mapper with "User attribute" type. For every new attribute that we want
Keystone to get information about a dedicated mapper need to be created. It
does not actually matter how exactly user attributes are named, it is
recommended to keep certain consistency and all 3 attributes "name", "user
attribute" and "token_claim_name" to use same value. Here we use "openstack-"
prefix for attributes


![Client Scope](../images/keycloak_client_scope_mapper.png)

In total we create following 2 mappers:

- openstack-user-name
- openstack-user-domain-name (feel free to go for domain_id if necessary, but
this may bite if Keystones are installed per region)

It is possible to define also something like "openstack-user-id" with a certain
unique ID of the user, we are going to rely on the unique ID of the user in the
Keycloak itself which is automatically available as "sub" (subject).

It is important to remember that if the client scope is not configured as a
"Default" type the data it is exposing may not become visible without
explicitly requesting this scope. It is just safe to make it default.

Next it we are going to create a user with the attributes configured above

![User attributes](../images/keycloak_user_attributes.png)
**NOTE:** It is very important to populate attributes for users otherwise they
will fail to get Keystone token without much useful information.

With this Keycloak configuration can be considered as "Done"

# Keystone configuration

In order to understand certain values required in the Apache configuration we
are going to configure Keystone itself next. It is also a pretty strait forward process

## Identity Provider

We need to register Keycloak as an identity provider in Keystone. This can be
achieved using
[api](https://docs.openstack.org/api-ref/identity/v3-ext/#register-an-identity-provider) or the OpenStackClient

```console
$ openstack identity provider create --remote-id https://localhost:8443/realms/master keycloak
```

You can specify in which domain it is going to be created and until recently
that would mean that all users of this Identity provider would be also
belonging to this domain. Now this does not matter anymore and IDP can be
created in any suitable domain (of course that no end customer has access to).
Additionally certain description can be used and is highly recommended.
`remote-id` is something that builds a match between Keystone and Keycloak and
must be pointing to the realm in Keycloak where the client has been configured
in the previous step.

## Mapping

Next step is to configure which attribute of Keycloak means what to the
Keystone. It is done using `mapping` and can be done using
[api](https://docs.openstack.org/api-ref/identity/v3-ext/#create-a-mapping) or
using the OpenStackClient. However this is the first time things are becoming a
bit more complex and need to be done pretty carefully.


#### mapping.json
```json {filename="m.json"}
[
  {
    "remote": [
      {
        "type": "OIDC-preferred_username"
      },
      {
        "type": "OIDC-email"
      },
      {
        "type": "OIDC-sub"
      },
      {
        "type": "OIDC-openstack-user-domain-name"
      }
    ],
    "local": [
      {
        "user": {
          "type": "ephemeral",
          "name": "{0}",
          "id": "{2}",
          "email": "{1}",
          "domain": {
            "name": "{3}"
          }
        }
     }
    ]
  }
]
```

*Note: Example above describes content of the `rules` property of the API call
or the file content that is being imported using OpenStackClient*

```console
$ openstack mapping create --rules mapping.json keycloak-mapping
```

The above configuration describes that:

- `OIDC-preferred_username` attribute coming to Keystone from "remote" (in next
chapter we will have a look on how and why Apache plays role on the attribute
names) is mapped on the "local" side (Keystone) to the user name (since
"remote" block is a list we must refer here by the index).

- `OIDC-email` remote attribute is used as user email

- `OIDC-sub` (remember the "sub" mentioned few chapters above as a Keystone
unique internal user UUID) is becoming the user_id in the Keystone. *Note:
technically speaking this is not the user_id in the Keystone, but used to
uniquely identify remote user*

- `OIDC-openstack-user-domain-name` is becoming user_domain_name attribute

The mapping also describes which roles the user becomes and which projects it
has access to. However this is a very static configuration and there is no
reasonable way to keep this information in sync with the real Identity source.
This is a subject of changes currently being addressed and as such a topic for
the next part of the series. Since in real life such static configuration is
barely useful in a multi-domain setup we are not going to use it at all. Feel
free to consult [official
documentation](https://docs.openstack.org/keystone/latest/admin/federation/mapping_combinations.html)
on further mapping capabilities.

In the next chapter we will see where those remote attributes are coming from.

## Protocol

Last, but not least, we need to connect Identity provider and the mapping. Also
this can be achieved by both
[api](https://docs.openstack.org/api-ref/identity/v3-ext/#add-protocol-to-identity-provider)
or the OpenStackClient.

```console
$ openstack federation protocol create openid --mapping keycloak_mapping --identity-provider keycloak
```

This marks end of basic Keystone configuration.

# Apache configuration (mod_oidc)

Keystone itself does not support OpenIDConnect, but it can use
[mod_oidc](https://docs.openstack.org/keystone/latest/admin/federation/configure_federation.html#configuring-an-httpd-auth-module)
of Apache web server to take over full protocol communication.

There is no full configuration available in the Keystone documentation, but
there is a working configuration file used in the functional tests. For us here
only certain parts of it are required:

#### /etc/httpd/conf.d/keystone-oidc.conf

```config
OIDCSSLValidateServer Off
OIDCOAuthSSLValidateServer Off
OIDCCookieSameSite On

OIDCClaimPrefix "OIDC-"
OIDCResponseType "id_token"
# List of attributes that the user will authorize the Identity Provider to send to the Service Provider
OIDCScope "openid email profile" 
OIDCProviderMetadataURL "https://localhost:8443/realms/master/.well-known/openid-configuration"
# Data (client_id and secret) of the Client created in the Keycloak
OIDCClientID "devstack"
OIDCClientSecret "nomoresecret"

# mod_auth_oidc internal data protection (no effect on the client)
OIDCPKCEMethod "S256"
OIDCCryptoPassphrase "openstack"

# vanity URL that must point to a protected path that does not have any content, such as an extension of the protected federated auth path.
OIDCRedirectURI "http://localhost:5000/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso"
OIDCRedirectURI "http://localhost:5000/v3/auth/OS-FEDERATION/websso/openid"

<Location "/v3/auth/OS-FEDERATION/websso/openid">
     AuthType "openid-connect"
     Require valid-user
</Location>

<Location "/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso">
    AuthType "openid-connect"
    Require valid-user
</Location>

<Location "/v3/auth/OS-FEDERATION/identity_providers/keycloak/protocols/openid/auth">
    AuthType "openid-connect"
    Require valid-user
</Location>

# IDP Endpoint for token validation
OIDCOAuthVerifyJwksUri "https://localhost:8443/realms/master/protocol/openid-connect/certs"

# Location a non-browser apps can communicate with
<Location ~ "/v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/auth">
    # AuthType here is not "openid-connect" since apps going here do not support browser flow
    AuthType "auth-openidc"
    Require valid-user
</Location>
```

Also here there are plenty of things that can be configured differently
(perhaps correct statement here is: wrong), especially since it all depends on
how exactly Keystone itself is being running (i.e. as uwsgi app or not) and
which ports are being exposed. What is important is that
`OIDCProviderMetadataURL` here points to the Keycloak we configured above (the
URL need to point to to the correct Keycloak realm where the client was
configured), `OIDCClientID` and `OIDCClientSecret` match ID and password of the
client.

In previous chapter we have seen that "remote" attributes of the Keystone
mapping all have "OIDC-" prefix. `OIDCClaimPrefix` is where it is configured.

For non-browser applications a dedicated endpoint is exposed that is not
expecting apps to do a regular authentication. We explicitly set the `AuthType`
for that to "auth-openidc" (actually "oauth20" is working absolutely same way
and can be interchanged).
[mod_auth_openidc](https://github.com/OpenIDC/mod_auth_openidc/wiki/OAuth-2.0-Resource-Server#keycloak)
describes 2 different approaches of the access token validation: remote and
local. Depending on the preferred choice configuration must be extended with
either `OIDCOAuthVerifyJwksUri` or with `OIDCOAuthIntrospectionEndpoint` +
`OIDCOAuthClientID` + `OIDCOAuthClientSecret`

Depending on whether the Horizon is being used or not and which authentication
methods users need to use there other parts that need to be configured, but
that is not belonging to the Keystone-Keycloak communication directly.
Therefore we can consider configuration as complete. Now if Keystone is started
as uwsgi app (according to the Apache config above), Apache server started and
running and Keycloak being available a user trying to authenticate in the Web
Browser
(http://localhost:5000/v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso?origin=http://localhost:5050)
would be redirected to the Keycloak for authentication after which the browser
will redirect to the "http://localhost:5050" as entered in the "origin" URI
parameter with the OpenStack token being part of the request.

# Keystone configuration

Once the federation itself is established it is time to apply final tweaks into
the Keystone configuration file to enable authentication.

#### keystone.conf 

```config
...
[auth]
# Add openid into the list of accepted auth methods
methods = password,token,openid,...
...

[federation]
remote_id_attribute = HTTP_OIDC_ISS
trusted_dashboard = ...
```

First change here is to add `openid` into the list of accepted authentication
methods in `auth.methods` property.

It is also necessary to set `federation.remote_id_attribute` to `HTTP_OIDC_ISS`
what is tied to the mod_auth_openidc configuration. See [official Keystone
docs](https://docs.openstack.org/keystone/latest/admin/federation/configure_federation.html#configure-the-remote-id-attribute)
for detailed explanation.

Last, but not least, it is required to extend `federation.trusted_dashboard`
configuration option with the list of the dashboards and other URLs that the
Keystone should be able to redirect user back in the browser once the
authentication has succeeded.

## Resource Owner Password Credentials Grant

User can use username and password for authentication. This flow is enabled by
"Direct access grant" client configuration option in Keycloak. 


#### clouds.yaml for OpenStackClient

```yaml
clouds:
  federated:
    auth_type: v3oidcpassword
    auth:
      auth_url: http://localhost:5000
      username: foo
      password: bar
      identity_provider: keycloak
      discovery_endpoint: https://localhost:8443/realms/master/.well-known/openid-configuration
      client_id: keystone
      client_secret: i5qKBsiBUewGwgexmDu3Pk8eI8ktPBvO
      protocol: openid
    verify: false
```

With this configuration OpenStackClient fetches IDP relevant information from
"discovery_endpoint" and peforms direct communication with it in order to
obtain an access token. With it it then performs the next call to
"`http://localhost:5000`/v3/OS-FEDERATION/identity_providers/`keycloak`/protocols/`openid`/auth"
(auth_url, identity_provider and protocol from the configuration are used to
construct this path). This is exactly the Location in the Apache configuration
with the `auth-openidc` configuration. Instead of the discovery_endpoint it is
possible to specify `access_token_endpoint` directly.

There are few major issues isung this approach 

- No support for MFA. Once user enables additional account protection (
actually one of the reasons somebody may want to have a IDP is to enforce and
control certain security aspects) this method stops working.

- Need to have user password outside the IDP. With OAuth and OpenIDConnect this
is exactly what we want to prevent

- Need for the user to know IDP details. User need to know IDP endpoint. But
what is worse is a need to also know client_id and client_secret. This makes it
not really usable in a wide scope.

## Authorization Code Grant and the remaining OAuth flows

This is currently a recommended way of user authentication. Sadly it is not
properly supported in the OpenStackClient as of now. There is an existing OSC
plugin available
[here](https://github.com/IFCA-Advanced-Computing/keystoneauth-oidc/tree/master)
which is, however, not capable to work with upstream Keystone

Since the plugin has no direct relation towards the OpenStack upstream
community it is left without further comments here.

OAuth2 and OpenIDConnect in most cases require knowing the Client created in
the IDP (client_id, client_secret). That means that a separate set of access
data is required that user must maintain. What is also representing a challenge
is that this requires making the client publicly available (since it is
impossible to assume that client_secret will remain secret). Due to this fact
and availability of the mod_auth_oidc another way is the preferred one.

## mod_auth_oidc as OAuth2/OpenID Connect Relying Party

mod_auth_oidc is configured with a dedicated client on the IDP. When a user
attempts to access protected resources the request is being redirected towards
the IDP starting a transparent for the user Authorization Code (or Token) grant
authentication. Once user successfully authenticates with the IDP he is
redirected back to the requested "trusted_dashboard". This redirect will arrive
as a POST request with OpenStack token present in the request body. The process
is so transparent that no OAuth2/OpenIDConnect libraries are required. In the
Keystone this flow is represented under the "websso" endpoint.

Single Sign On is currently not supported in python-openstackclient. A new
experimental OpenStack CLI [osc](https://github.com/gtema/openstack) is
addressing this gap and tries to deal with authentication differently trying to
save user from unnecessary re-authentication upon every time a session is being
established

Following `clouds.yaml` configuration is sufficient for that usecase.
```yaml
clouds:
  federated:
    auth_type: v3websso
    auth:
      auth_url: http://localhost:5000
      identity_provider: keycloak
      protocol: openid
```

The `osc` starts webserver listening on the `http://localhost:8050/callback`
and it is required to explicitly allow this URL in the list of trusted
dashboards in the `keystone.conf`.

**NOTE:** SSO by default relies on the user interaction (with user interacting
with the IDP in the browser), therefore also this method is hardly applicable
for the machine to machine usecase

In the next part we are going to have a deeper look on what is required to
implement dynamic mapping of federated users to projects and groups/roles with
data maintained by the IDP itself. Since this is still not implemented in the
Keystone it will describe current state of things.
