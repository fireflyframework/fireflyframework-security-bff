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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;
import java.util.Set;

/**
 * Makes RP-initiated logout XHR-aware.
 *
 * <p>Wraps the delegate {@link ServerLogoutSuccessHandler} (an
 * {@link org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler}):
 * a browser document request (Accept: text/html) still gets the classic {@code 302} to the IdP
 * end-session endpoint, while a {@code fetch}/XHR caller gets {@code 200} + {@code {"logoutUrl":"<same
 * end-session URL>"}} so a SPA can drive the navigation itself instead of choking on a cross-origin
 * redirect it cannot follow.</p>
 *
 * <p>Relies on the delegate only <em>setting</em> the redirect status and {@code Location} (deferred,
 * not committed): the response is still mutable, so rewriting it to a {@code 200} JSON body for the XHR
 * branch is safe and needs no response decorator.</p>
 */
final class XhrAwareLogoutSuccessHandler implements ServerLogoutSuccessHandler {

    private final ServerLogoutSuccessHandler delegate;
    private final MediaTypeServerWebExchangeMatcher htmlMatcher;
    private final ObjectMapper objectMapper;

    XhrAwareLogoutSuccessHandler(ServerLogoutSuccessHandler delegate, ObjectMapper objectMapper) {
        this.delegate = delegate;
        this.objectMapper = objectMapper;
        // Same browser-vs-XHR criterion as BffSecurityAutoConfiguration#browserAwareEntryPoint:
        // a request explicitly asking for text/html is a browser document load; everything else
        // (fetch/XHR, which sends Accept: */* or application/json) is treated as programmatic.
        this.htmlMatcher = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
        this.htmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
    }

    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        ServerWebExchange webExchange = exchange.getExchange();
        // Let the delegate build the end-session URL and set 302 + Location (deferred, uncommitted).
        return delegate.onLogoutSuccess(exchange, authentication)
                .then(htmlMatcher.matches(webExchange))
                .flatMap(match -> {
                    if (match.isMatch()) {
                        return Mono.empty(); // browser: keep the 302 the delegate set
                    }
                    ServerHttpResponse response = webExchange.getResponse();
                    if (response.isCommitted()) {
                        return Mono.empty(); // can't rewrite a committed response; leave the redirect
                    }
                    URI location = response.getHeaders().getLocation();
                    response.getHeaders().setLocation(null);
                    response.setStatusCode(HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    DataBuffer buffer = response.bufferFactory().wrap(writeBody(location));
                    return response.writeWith(Mono.just(buffer));
                });
    }

    private byte[] writeBody(URI location) {
        try {
            return objectMapper.writeValueAsBytes(
                    Map.of("logoutUrl", location == null ? "" : location.toString()));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize logout response", e);
        }
    }
}
