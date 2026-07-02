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

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/** Unit tests for {@link SpaServerCsrfTokenRequestHandler}. */
class SpaServerCsrfTokenRequestHandlerTest {

    private final SpaServerCsrfTokenRequestHandler handler = new SpaServerCsrfTokenRequestHandler();
    private final CsrfToken token = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "raw-cookie-value");

    @Test
    void headerToken_isResolvedRaw_notXorDecoded() {
        // The SPA reads the raw token from the XSRF-TOKEN cookie and echoes it in the header; it must
        // validate as-is (plain), not be run through XOR un-masking.
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/logout").header("X-XSRF-TOKEN", "raw-cookie-value"));

        StepVerifier.create(handler.resolveCsrfTokenValue(exchange, token))
                .expectNext("raw-cookie-value")
                .verifyComplete();
    }

    @Test
    void handle_doesNotThrow() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        handler.handle(exchange, Mono.just(token)); // renders via XOR into the request attributes
    }
}
