+++
title = "Rethinking Auth or OpenStack user in client applications"
description = "Rethinking Auth or OpenStack user in client applications"
date = "2024-01-20"
author = "Artem Goncharov"
+++

# Rethinking Auth or OpenStack user in client applications

## Basics

Keystone is an Identity and Access Management part of OpenStack. It has a great
flexibility providing variety ways of authentication and authorization. Every
API invocation should be authenticated with an authentication token:

```
$> curl -H "X-Auth-Token: my_secret_value" https://compute.test.com/v2.1/servers

```

The flexibility comes into the game as an answer to question: where do I get a
token. There are plenty of different ways, among others:

- user credentials (with support for multifactor authentication)

- client SSL certificate

- another Api token (from previous authentication or in a IAM federation)

- OAuth2

- OpenIDConnect

- SAML2

- Application credentials

Every token contain expiration information and the scope (authorization part).
There are also different possible scopes, but the major ones are:

- unscoped (user is not really allowed to do anything)

- project scope (user is allowed to do something in a scope of a certain
  project)

- domain scope (API access bound to a certain domain)

## Challenges

Current OpenStack client tooling tries to support all of the Keystone
capabilities, however some of them require a very special treatment. I was
personally asked multiple times same questions, observed people struggled
themselves through not properly documented capabilities or ever developing
their own workarounds. Every time this feels like a face-palm moment. Here are
the most prominent issues

### MFA

How is the cli or a script supposed to perform a multi-factor authentication?
Actually here is some sort of contradiction - a process which is supposed to be
executed in a headless mode or by cron is not a user and is not capable to
do MFA. Maybe soon AI would be able to get the virtual mobile phone from the
virtual pocket and see the verification code on it, but this is not the case
right now. That means all those headless processes should either use dedicated
automation users created without MFA enabled for them or switch to alternative
means of authentication (application credentials, SSL certificates, etc)

### SSO

How is it possible to authenticate the CLI or Ansible process when it requires
Webbrowser to obtain a valid session token? This is relatively similar to the
MFA usecase and it also requires that all automation processes use alternative
authentication ways, But still, when user it triggering Ansible playbook with
personal credentials, how should this work?

### Caching

Depending on the Keystone configuration every token has certain validity
spanning from 1h (default in the DevStack) up to 24h (at least this is the
maximum I have seen in the wild by certain public clouds). Technicall there is
no upper limit, but keeping the token valid too long poses serious security
risks.

Obtaining a token is not an expensive operation and is usually a matter of
50-100ms. However some public clouds have scaling issues and this all of a
sudden takes up to 1 second. As a one time operation there is no problem with
that even it would be 1 second but without caching every consequent CLI
invocation or every following Ansible task would have a sensible delay. Now,
remember the MFA and SSO questions from above, would this every following
invocation require another extra steps? This makes authentication caching
inevitable in a real life.

### Catalog

This item is closely coupled with token caching, since by default
authentication token is also containing authorization information including API
catalog (a list of API endpoints that should be used for further
communication). Now if we cache only token we would need to refetch catalog on
every start. This does not look like an effective solution and the most logical
thing may sound that the catalog information should be cached as well. One of
the first things I faced implementing that were the failures in the DevStack
installation. Reason for that is as simple as complex it is: a token is used to
modify catalog configuration. A new service is being added into the catalog and
upon the next CLI invocation it is simply unknown. That means catalog caching
is better then not doinf that, but at the same time this is creating new
challenges.

### Encryption

"If we cache token on the file system, it must be encrypted".

Well, this makes really no sense since even the raw credentials are stored in
plain text in the `clouds.yaml` file.

## Rethinking

User experience is one the crucial things I am personally striving for and I
decided to give it a try and rethink cardinally how the authentication and
authorization are handled in the user facing applications. Since I am working
on creating new experimental CLI for OpenStack I tried to implement it there
rather then start breaking existing tools (especially that it may not be even
technically possible).

Majority of existing good CLIs are often having a `<cli_name> auth login` or
similar commands. This performs authentication relying on whichever method is
possible and user interaction (for entering MFA code or entering credentials in
webbrowser with SSO or whatsoever). Once authentication is performed the token
can be stored on the file system. Every consequent access should try to reuse
existing valid token. In the case when access is required for the different
scope (another project or domain) we should try to get new authorization for
the desired scope using valid authentication (a token from token). This new
authorization should be also added into the cache for future use.

### Cache organization

Storing different authentications and authorizations in the cache requires a
good storage scheme. A two dimensional matrix seems to be a possible solution
here. Since caching should be also working in the regular headless mode we
should not try to use any of the key wallets and/or rely on DBus with secrets
storage. That means data should be stored on the file system. Encrypting data
makes also not so much sense since decrypting requie passing additional
decryption secrets. So at least for now we just store cache in regular plain
text files (remember user password is also located in a plain text form on FS).
In order to make caching reasonably simple a first dimension of the caching can
be done on a file base. That means that one file keeps all authorization data
for single authentication. To make this clearer now imagine calculating a hash
of authentication endpoint plus authentication (no scope authorization) data.
This gives us a file name. Next in a file tokens for different scopes can be
stored with their corresponding expiration information to be able to drop
outdated information. 

Next question is: what is the key in file? It is the scope, but the scope is
actually a complex structure containing project id/name, domain id/name and
maybe something else (system scope). Simply calculating hash of this data and
use it as a key may sound like reasonable solution, but how do we search for
available authorization data when we know only part of the data (when we first
requested authorization we passed only project name, once authorized we know
also project id and domain information this project belongs to, now we search
for authorization using the project id). That require that as a key we should
actually use the full authorization information and do a logical search with
multiple match branches.

With all of that said following describes the caching:

- single file per authentication information (auth endpoint + authentication
information)
- cache file can be represented as a hashmap with scope structure as a key and
a token data as a value. This hashmap can be serialized into the binary form
(json/yaml/toml definitely do not suit here).

Previous attempt with token caching in OpenStackSDK resulted in sporadic
failures in DevStack tests where few processes could write into the single file
currupting it. That puts a strict requirement that cache corruption should not
break the process. When cache file is corrupted it must be just silently
dropped, as well as all expired information should be filtered out from a valid
file. Additionally a user guiding information about cache file location should
be also given when certain unrecoverable situations happen.

```
$> osc auth login
```

This command will perform authentication (authorization) interactively using
browser when necessary or further requesting entering MFA code and prints token
to the stdout (similarly to `vault login -oidc ...`) togeteher with saving auth
information in the cache. Printing token to the stdout makes it possible to be
used together with the existing OpenStack tools. Following `osc` invocations
will access the cache information and reuse it even for different scopes while
at least any of the authorization tokens remain valid.
