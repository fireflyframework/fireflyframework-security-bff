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
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * CSRF request handler for a cookie-based SPA (Spring's documented pattern).
 *
 * <p>Rendering uses the BREACH-safe {@link XorServerCsrfTokenRequestAttributeHandler} (masked token).
 * Resolution is where a cookie-based SPA differs from a server-rendered form: the SPA reads the raw
 * token from the {@code XSRF-TOKEN} cookie and echoes it back in the request header, so when a header
 * is present the value is resolved with the plain {@link ServerCsrfTokenRequestAttributeHandler}
 * (raw, un-masked); otherwise (e.g. a form {@code _csrf} parameter) it falls back to the XOR handler.
 * Without this, the default XOR handler tries to un-mask the raw cookie value and rejects it (403).</p>
 */
public final class SpaServerCsrfTokenRequestHandler implements ServerCsrfTokenRequestHandler {

    private final ServerCsrfTokenRequestHandler xor = new XorServerCsrfTokenRequestAttributeHandler();
    private final ServerCsrfTokenRequestHandler plain = new ServerCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
        this.xor.handle(exchange, csrfToken);
    }

    @Override
    public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
        String headerValue = exchange.getRequest().getHeaders().getFirst(csrfToken.getHeaderName());
        ServerCsrfTokenRequestHandler handler = StringUtils.hasText(headerValue) ? this.plain : this.xor;
        return handler.resolveCsrfTokenValue(exchange, csrfToken);
    }
}
