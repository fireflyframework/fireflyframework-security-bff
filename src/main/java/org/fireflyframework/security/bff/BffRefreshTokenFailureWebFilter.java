/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.bff;

import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Turns a dead-session token failure into a clean, actionable response.
 *
 * <p>When the gateway {@code TokenRelay} asks the session-bound authorized-client manager for a valid
 * access token and the refresh token is expired/revoked (or no authorized client exists yet), a
 * {@link ClientAuthorizationException} propagates out of the manager (the refresh provider maps the
 * IdP {@code invalid_grant} into it, and neither the manager nor the TokenRelay filter transforms it).
 * Left unhandled it surfaces to the SPA as an opaque 500. This filter catches it, invalidates the
 * (Redis-backed) session so the next call starts a fresh login, and answers:</p>
 * <ul>
 *   <li>a browser document request (Accept: text/html) with {@code 302} to the login endpoint;</li>
 *   <li>a {@code fetch}/XHR caller with {@code 401} + {@code {"loginUrl":"/oauth2/authorization/<id>"}}
 *       so the SPA can consciously restart the login.</li>
 * </ul>
 *
 * <p>Only <em>dead-session</em> failures are converted: {@code invalid_grant}/{@code invalid_token} and
 * "authorization required". A transient IdP failure (timeout, 5xx, other error codes) is re-thrown so
 * the caller sees a 5xx and can retry, instead of being needlessly logged out. This mirrors the
 * selectivity of Spring's own {@code RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}.</p>
 *
 * <p>Ordered at {@code -101}, just outside Security's {@code WebFilterChainProxy} ({@code -100}), so the
 * {@code onErrorResume} wraps the whole Security + gateway pipeline. As defence in depth, requests on
 * the OAuth handshake endpoints ({@code /oauth2/authorization/**}, {@code /login/oauth2/code/**}) are
 * excluded — a login-code-exchange failure is Spring Security's to handle, not a dead-session relay
 * failure (it surfaces as an {@code AuthenticationException} and is consumed inside the security chain
 * before reaching here, but the guard keeps this filter honest).</p>
 */
public final class BffRefreshTokenFailureWebFilter implements WebFilter, Ordered {

    /** Just outside Security's {@code WebFilterChainProxy} (-100) so it wraps the whole chain. */
    static final int ORDER = -101;

    /** OAuth2 error codes that mean the stored authorization is dead and re-login is required. */
    private static final Set<String> DEAD_SESSION_CODES = Set.of("invalid_grant", "invalid_token");

    private final String loginPath;
    private final String authorizationPrefix;
    private final String callbackPrefix;
    private final MediaTypeServerWebExchangeMatcher htmlMatcher;

    public BffRefreshTokenFailureWebFilter(BffSecurityProperties properties) {
        String registrationId = properties.getRegistrationId();
        this.loginPath = "/oauth2/authorization/" + registrationId;
        this.authorizationPrefix = "/oauth2/authorization/";
        this.callbackPrefix = "/login/oauth2/code/";
        this.htmlMatcher = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
        this.htmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
                .onErrorResume(ClientAuthorizationException.class, ex -> {
                    if (isOnAuthHandshakePath(exchange) || !isDeadSession(ex)) {
                        // Login-in-progress or a transient failure: let it propagate untouched.
                        return Mono.error(ex);
                    }
                    return exchange.getSession()
                            .flatMap(WebSession::invalidate)
                            .then(Mono.defer(() -> respond(exchange)));
                });
    }

    /** A dead/absent authorization the user can only recover from by logging in again. */
    private boolean isDeadSession(ClientAuthorizationException ex) {
        if (ex instanceof ClientAuthorizationRequiredException) {
            return true; // no authorized client for this session — must re-authorize
        }
        return ex.getError() != null && DEAD_SESSION_CODES.contains(ex.getError().getErrorCode());
    }

    private boolean isOnAuthHandshakePath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        return path.startsWith(authorizationPrefix) || path.startsWith(callbackPrefix);
    }

    private Mono<Void> respond(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            // The downstream already started streaming a response; can't cleanly rewrite it.
            return Mono.empty();
        }
        return htmlMatcher.matches(exchange).flatMap(match -> {
            if (match.isMatch()) {
                response.setStatusCode(HttpStatus.FOUND); // browser: restart login
                response.getHeaders().setLocation(URI.create(loginPath));
                return response.setComplete();
            }
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            // loginPath is derived from the configured registration-id (a controlled token), so a
            // hand-built JSON body is safe here — no user input reaches it.
            byte[] body = ("{\"loginUrl\":\"" + loginPath + "\"}").getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(body);
            return response.writeWith(Mono.just(buffer));
        });
    }
}
