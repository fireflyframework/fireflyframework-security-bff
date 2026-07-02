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

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Materializes the CSRF token so the {@code XSRF-TOKEN} cookie is actually delivered to the browser.
 *
 * <p>Since Spring Security 5.8/6.0 the CSRF token is <em>deferred</em> (loaded only when accessed, a
 * BREACH mitigation). With a {@code CookieServerCsrfTokenRepository} that means the {@code XSRF-TOKEN}
 * cookie is written only when something reads the token — and a token-handler BFF has no application
 * handler that does, so a SPA never receives it and cannot echo it back on state-changing requests
 * (most visibly {@code POST /logout}, which is CSRF-protected).</p>
 *
 * <p>This filter subscribes to the deferred {@link CsrfToken} on every request, forcing the repository
 * to emit the cookie. It runs after Spring Security's {@code CsrfWebFilter} has published the token as
 * an exchange attribute (this bean carries the default lowest precedence, i.e. closest to the handler),
 * and is a no-op when CSRF is disabled (no attribute present).</p>
 */
public final class CsrfCookieWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
        if (csrfToken == null) {
            return chain.filter(exchange); // CSRF disabled — nothing to render
        }
        // Subscribing resolves the deferred token, which makes the repository write the XSRF-TOKEN
        // cookie before the response is committed.
        return csrfToken.then(chain.filter(exchange));
    }
}
