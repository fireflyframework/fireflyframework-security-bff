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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link BffRefreshTokenFailureWebFilter}: a dead-session token failure surfacing from
 * the (downstream) gateway TokenRelay is translated to a clean 401 (XHR) / 302 (browser), while
 * login-handshake failures, transient failures and unrelated errors are left to propagate.
 */
class BffRefreshTokenFailureWebFilterTest {

    private static final String LOGIN = "/oauth2/authorization/idp";

    private final BffRefreshTokenFailureWebFilter filter =
            new BffRefreshTokenFailureWebFilter(new BffSecurityProperties()); // registration-id = "idp"

    private static WebFilterChain failing(Throwable error) {
        return exchange -> Mono.error(error);
    }

    /** What the refresh provider raises on a dead/revoked refresh token (IdP {@code invalid_grant}). */
    private static ClientAuthorizationException deadRefresh() {
        return new ClientAuthorizationException(new OAuth2Error("invalid_grant"), "idp");
    }

    @Test
    void order_isJustOutsideSecurityChain() {
        assertThat(filter.getOrder()).isEqualTo(-101);
    }

    @Test
    void xhrDeadRefresh_becomes401WithLoginUrl() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(filter.filter(exchange, failing(deadRefresh()))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        StepVerifier.create(exchange.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).isEqualTo("{\"loginUrl\":\"" + LOGIN + "\"}"))
                .verifyComplete();
    }

    @Test
    void browserDeadRefresh_becomes302ToLogin() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.TEXT_HTML));

        StepVerifier.create(filter.filter(exchange, failing(deadRefresh()))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isEqualTo(URI.create(LOGIN));
    }

    @Test
    void authorizationRequired_isTreatedAsDeadSession() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(filter.filter(exchange, failing(new ClientAuthorizationRequiredException("idp"))))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void transientIdpFailure_isNotConvertedAndPropagates() {
        // A non-dead-session error code (e.g. IdP briefly down) must NOT log the user out.
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));
        ClientAuthorizationException transientErr =
                new ClientAuthorizationException(new OAuth2Error("server_error"), "idp");

        StepVerifier.create(filter.filter(exchange, failing(transientErr)))
                .expectError(ClientAuthorizationException.class)
                .verify();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void baseOAuth2AuthorizationException_isNotIntercepted() {
        // Only the ClientAuthorization* subtype (what the relay raises) is handled; the bare base
        // exception from other flows propagates untouched.
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(filter.filter(exchange,
                        failing(new OAuth2AuthorizationException(new OAuth2Error("invalid_grant")))))
                .expectError(OAuth2AuthorizationException.class)
                .verify();
    }

    @Test
    void deadRefreshOnLoginCallbackPath_isLeftToSecurity() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/login/oauth2/code/idp").accept(MediaType.TEXT_HTML));

        StepVerifier.create(filter.filter(exchange, failing(deadRefresh())))
                .expectError(ClientAuthorizationException.class)
                .verify();
    }

    @Test
    void deadRefreshOnAuthorizationPath_isLeftToSecurity() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/oauth2/authorization/idp").accept(MediaType.TEXT_HTML));

        StepVerifier.create(filter.filter(exchange, failing(deadRefresh())))
                .expectError(ClientAuthorizationException.class)
                .verify();
    }

    @Test
    void unrelatedError_propagates() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(filter.filter(exchange, failing(new IllegalStateException("boom"))))
                .expectError(IllegalStateException.class)
                .verify();
    }

    @Test
    void successfulRequest_passesThroughUntouched() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/backoffice/whatever").accept(MediaType.APPLICATION_JSON));

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty())).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }
}
