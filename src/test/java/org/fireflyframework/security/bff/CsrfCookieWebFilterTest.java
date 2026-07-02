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
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link CsrfCookieWebFilter}. */
class CsrfCookieWebFilterTest {

    private final CsrfCookieWebFilter filter = new CsrfCookieWebFilter();

    @Test
    void subscribesDeferredTokenThenProceeds() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        AtomicBoolean tokenSubscribed = new AtomicBoolean(false);
        Mono<CsrfToken> token = Mono.<CsrfToken>just(new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "v"))
                .doOnSubscribe(s -> tokenSubscribed.set(true));
        exchange.getAttributes().put(CsrfToken.class.getName(), token);

        AtomicBoolean chained = new AtomicBoolean(false);
        WebFilterChain chain = e -> Mono.fromRunnable(() -> chained.set(true));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(tokenSubscribed).as("deferred token must be subscribed to emit the cookie").isTrue();
        assertThat(chained).as("chain must still proceed").isTrue();
    }

    @Test
    void noCsrfAttribute_justProceeds() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        AtomicBoolean chained = new AtomicBoolean(false);
        WebFilterChain chain = e -> Mono.fromRunnable(() -> chained.set(true));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(chained).isTrue();
    }
}
