# Firefly Framework - Security BFF

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x-brightgreen.svg)](https://spring.io/projects/spring-security)

> Secure-by-default **token-handler BFF** for Spring WebFlux. A single auto-configuration turns a reactive application (typically a Spring Cloud Gateway) into the confidential OAuth client that runs Authorization Code + PKCE server-side, keeps the user's tokens in the server-side session, and hands the browser only an opaque `__Host-` cookie — no token ever reaches the browser, and no security code is required.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits in the platform](#where-it-sits-in-the-platform)
- [What it provides](#what-it-provides)
- [Key types](#key-types)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Why not `security-oauth2-client`](#why-not-security-oauth2-client)
- [Login & relay flow](#login--relay-flow)
- [Testing](#testing)
- [License](#license)

## Overview

This module is the **token-handler BFF binding** of the Firefly hexagonal security platform. It implements the [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) *token-handler* pattern: the browser authenticates against a confidential server-side client, the tokens never leave the server, and the browser holds only an opaque, `HttpOnly`, `__Host-`-prefixed session cookie.

It is deliberately product-agnostic and **Spring-Cloud-Gateway-agnostic**: it contributes only the security chain and a per-user, session-bound authorized-client manager. Routing, the `TokenRelay` filter and trusted-header stripping stay in the consuming application. The whole module is one `@AutoConfiguration` class (`BffSecurityAutoConfiguration`) plus a properties class. Every bean it contributes is `@ConditionalOnMissingBean`, so an application can override any single piece — the filter chain, the entry point, the logout handler, the authorized-client manager — without forking the module.

## Where it sits in the platform

The security platform is layered hexagonally; this module is the **edge / confidential-client binding**, a sibling of the resource-server binding:

```
security-api  →  security-spi  →  security-core  →  security-webflux  →  security-bff           →  application
 (ports +         (driven           (neutral          (reactive             (this module:             (Spring Cloud
  domain)          ports)            engine)            Spring Security        oauth2Login token-        Gateway: routes +
                                                        bindings)              handler chain)            TokenRelay)
```

- **This module** wires Spring Security 6's reactive `oauth2Login` into the token-handler chain and exposes a session-bound `ReactiveOAuth2AuthorizedClientManager` so a gateway `TokenRelay` can attach the logged-in user's access token downstream.
- It pairs with **`security-resource-server`** on the other side of the call: the BFF relays a bearer token to services that this module's resource-server sibling validates.

This module depends only on Spring Security's OAuth2 client + reactive web stack; it imports no vendor SDK and does not require Spring Cloud Gateway at compile time.

## What it provides

`BffSecurityAutoConfiguration` contributes, each gated by `@ConditionalOnMissingBean`:

- **A token-handler `SecurityWebFilterChain`** (`bffSecurityWebFilterChain`):
  - **`oauth2Login` with forced PKCE.** A `DefaultServerOAuth2AuthorizationRequestResolver` with `OAuth2AuthorizationRequestCustomizers.withPkce()` so the authorization request always carries `code_challenge` (S256) — Spring enables PKCE automatically only for *public* clients, but a confidential token-handler must still send it (required when the IdP enforces PKCE).
  - **Default-deny authorization.** Only the configured `permit-matchers` are public; every other exchange requires authentication.
  - **Cookie-mode CSRF.** `CookieServerCsrfTokenRepository.withHttpOnlyFalse()` so a SPA can read and echo the `XSRF-TOKEN`.
  - **RP-initiated logout.** `OidcClientInitiatedServerLogoutSuccessHandler` clears the session and redirects to the IdP end-session endpoint.
  - **A browser-aware entry point.** A document request (`Accept: text/html`) is redirected to start the login (`/oauth2/authorization/<registrationId>`); everything else (XHR/fetch) gets a **401** so the SPA can trigger the login navigation itself.
- **A session-bound authorized-client manager** (`bffAuthorizedClientManager`): a `DefaultReactiveOAuth2AuthorizedClientManager` (authorization-code + refresh-token providers) that reads the token from the `ServerOAuth2AuthorizedClientRepository` (the WebSession, Redis-backed via Spring Session). A gateway `TokenRelay` uses this bean to attach the **logged-in user's** access token to downstream calls — not an M2M token.

## Key types

| Type | Role |
| --- | --- |
| `BffSecurityAutoConfiguration` | `@AutoConfiguration` entry point (`@ConditionalOnWebApplication(REACTIVE)`, `@ConditionalOnClass(ServerHttpSecurity, ReactiveClientRegistrationRepository)`); builds the token-handler `SecurityWebFilterChain` and the session-bound authorized-client manager. |
| `BffSecurityProperties` | `@ConfigurationProperties("firefly.security.bff")` — neutral `registration-id`, public `permit-matchers`, `post-logout-redirect-uri`. |

The auto-configuration is registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

## Requirements

- Java 21+
- Spring Boot 3.x, Spring Security 6.x
- A reactive web stack (Spring WebFlux); typically Spring Cloud Gateway in the consuming app for routing + `TokenRelay`
- An OAuth2 client registration (`spring.security.oauth2.client.*`) — confidential, Authorization Code
- A server-side session store (Spring Session; Redis in production) to hold the tokens off the browser
- HTTPS at the edge — the `__Host-` session cookie requires `Secure`

## Installation

The version is managed by the Firefly parent/BOM, so you can usually omit it. Depend on it directly in the BFF/gateway application:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-bff</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-bff</artifactId>
    <version>26.06.03</version>
</dependency>
```

## Quick Start

With the module on the classpath and an OAuth2 client registration configured, the token-handler chain is active with **zero security code**. The consuming gateway keeps its routes and the `TokenRelay` + header-stripping filters:

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          idp:
            issuer-uri: https://idp.example.com/realms/firefly
        registration:
          idp:
            provider: idp
            client-id: my-bff
            client-secret: ${BFF_CLIENT_SECRET}
            authorization-grant-type: authorization_code
            scope: openid, profile, email
            redirect-uri: "{baseUrl}/login/oauth2/code/idp"
  session:
    store-type: redis
  cloud:
    gateway:
      default-filters:
        - TokenRelay=
        - RemoveRequestHeader=X-Tenant-Id
        - RemoveRequestHeader=X-User-Id
      routes:
        - id: api
          uri: lb://downstream-service
          predicates:
            - Path=/api/**

firefly:
  security:
    bff:
      registration-id: idp
      permit-matchers:
        - /actuator/health/**
```

## Configuration

All keys live under `firefly.security.bff`:

| Property | Default | Description |
| --- | --- | --- |
| `registration-id` | `idp` | Spring OAuth2 client `registration-id`. Neutral on purpose (not the provider name) so the login endpoints are `/oauth2/authorization/<id>` and `/login/oauth2/code/<id>`. |
| `permit-matchers` | _(empty)_ | Ant-style paths served without authentication (e.g. actuator, docs). The OAuth2 login endpoints are handled by the login filter and need not be listed. |
| `post-logout-redirect-uri` | `{baseUrl}` | Where to send the browser after an RP-initiated logout completes at the IdP. |

The OAuth2 client itself (provider, client-id/secret, scopes, redirect-uri) is configured with the standard `spring.security.oauth2.client.*` keys, and the session store with `spring.session.*` — this module does not duplicate them.

## Why not `security-oauth2-client`

The framework's `security-oauth2-client` module is intentionally **not** used here. Its authorized-client manager is service/M2M-oriented (`client_credentials`); on a gateway it would hijack the `TokenRelay` and attach a **service** token instead of the logged-in **user's** token. This module fills that gap with a manager bound to the user's WebSession, which is exactly what the token-handler pattern needs.

## Login & relay flow

```
Browser (cookie)
  → /oauth2/authorization/<id>     → 302 to IdP /authorize (code_challenge S256)
  → IdP login
  → /login/oauth2/code/<id>        → server-side code→token exchange
  → tokens stored in the WebSession (Spring Session / Redis); browser gets an opaque __Host- cookie
  → API call (cookie, no bearer)   → TokenRelay reads the session-bound authorized client
                                    → adds Authorization: Bearer <user access token> downstream
```

An unauthenticated document request is redirected to the IdP login; an unauthenticated XHR gets **401**. The browser never receives or stores a token.

## Testing

The module ships a structural test, `BffSecurityAutoConfigurationTest`, that boots the real auto-configuration with a **static** (non-discovery) OAuth client registration so the context starts without a live IdP, Redis or Docker (session in-memory; Redis/Session autoconfig excluded). It asserts the secure-by-default behavior:

- the permit list is reachable without authentication;
- an unauthenticated XHR call returns **401**, while a browser document request is **redirected** to `/oauth2/authorization/<id>`;
- `oauth2Login` is wired under the neutral `registration-id` and the authorize redirect targets the IdP authorization endpoint.

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
