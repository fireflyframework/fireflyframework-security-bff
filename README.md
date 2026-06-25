# Firefly Framework - Security BFF

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x-green.svg)](https://spring.io/projects/spring-security)

> The **token-handler BFF** delivery module of the Firefly security platform. A single
> `@AutoConfiguration` turns a reactive application (typically a Spring Cloud Gateway) into the
> confidential OAuth client that runs the login server-side and keeps tokens off the browser.

## Overview

A token-handler **Backend-for-Frontend**: the SPA/mobile client never holds tokens. This module
wires the secure-by-default chain for that pattern on Spring WebFlux:

- **OAuth2 Login** (Authorization Code + PKCE) under a neutral `registration-id`, so the login
  endpoints are `/oauth2/authorization/<id>` and `/login/oauth2/code/<id>` (provider-agnostic).
- **Server-side tokens**: the access/refresh/ID tokens live in the reactive `WebSession`
  (Redis-backed via Spring Session in production); the browser receives only an opaque
  `__Host-` session cookie.
- **Per-user, session-bound `ReactiveOAuth2AuthorizedClientManager`** so a gateway `TokenRelay`
  filter attaches the *logged-in user's* access token downstream (not an M2M token).
- **Cookie-mode CSRF** (`XSRF-TOKEN` double-submit), **RP-initiated logout**, and a
  **browser-aware authentication entry point**: `401` for XHR/API, redirect-to-login only for
  browser document loads.

It is **Spring-Cloud-Gateway-agnostic**: it contributes only the security chain and the manager.
Routing, the `TokenRelay` filter and trusted-header stripping stay in the consuming application.

## Why not `security-oauth2-client`

`fireflyframework-security-oauth2-client` provides an outbound, **M2M** token-relay filter backed by
a service-based (in-memory, fixed-principal) authorized-client manager. A BFF needs a **per-user,
session-bound** manager; the M2M one would hijack the gateway's per-user relay. This module fills
that gap.

## Installation

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-bff</artifactId>
</dependency>
```

The consuming app provides the reactive web stack (e.g. `spring-cloud-starter-gateway`), the
OAuth2 client registration, and a session store (`spring-session-data-redis`).

## Configuration

```yaml
firefly:
  security:
    bff:
      registration-id: idp            # neutral; the OAuth2 registration-id
      post-logout-redirect-uri: "{baseUrl}"
      permit-matchers:
        - /actuator/health/**
        - /actuator/info
```

Every contributed bean is `@ConditionalOnMissingBean`, so any single piece (the chain, the manager,
the entry point) can be overridden.

## License

Apache License 2.0.
