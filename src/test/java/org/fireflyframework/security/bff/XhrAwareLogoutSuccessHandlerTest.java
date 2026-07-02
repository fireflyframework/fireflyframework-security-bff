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
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link XhrAwareLogoutSuccessHandler}. A fake delegate reproduces the real
 * {@link org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler}
 * behaviour (deferred 302 + Location, uncommitted), so the conversion to 200 + JSON for XHR is exercised
 * deterministically without an IdP.
 */
class XhrAwareLogoutSuccessHandlerTest {

    private static final String END_SESSION =
            "https://idp.test/realms/idp/protocol/openid-connect/logout?id_token_hint=abc&post_logout_redirect_uri=http://localhost:8090";

    /** Mirrors the real handler: only sets status + Location (deferred), never commits the response. */
    private final ServerLogoutSuccessHandler delegate = (exchange, authentication) ->
            Mono.fromRunnable(() -> {
                ServerHttpResponse r = exchange.getExchange().getResponse();
                r.setStatusCode(HttpStatus.FOUND);
                r.getHeaders().setLocation(URI.create(END_SESSION));
            });

    private final XhrAwareLogoutSuccessHandler handler =
            new XhrAwareLogoutSuccessHandler(delegate, new ObjectMapper());

    private WebFilterExchange exchangeFor(MockServerWebExchange exchange) {
        WebFilterChain noop = e -> Mono.empty();
        return new WebFilterExchange(exchange, noop);
    }

    @Test
    void xhrCallerGets200WithLogoutUrlJson() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/logout").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(handler.onLogoutSuccess(exchangeFor(exchange), null)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
        StepVerifier.create(exchange.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).contains("\"logoutUrl\"").contains(END_SESSION))
                .verifyComplete();
    }

    @Test
    void fetchWithWildcardAcceptIsTreatedAsXhr() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/logout").accept(MediaType.ALL));

        StepVerifier.create(handler.onLogoutSuccess(exchangeFor(exchange), null)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void browserNavigationKeeps302Redirect() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/logout").accept(MediaType.TEXT_HTML));

        StepVerifier.create(handler.onLogoutSuccess(exchangeFor(exchange), null)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isEqualTo(URI.create(END_SESSION));
    }
}
