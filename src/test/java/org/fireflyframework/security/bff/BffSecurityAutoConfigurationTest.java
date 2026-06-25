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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structural tests for {@link BffSecurityAutoConfiguration}, driven by a static (non-discovery) OAuth
 * client registration so the context starts without a live IdP, Redis or Docker. Proves default-deny,
 * the permit list, the XHR-vs-browser entry point, and that oauth2Login is wired under the configured
 * registration-id.
 */
@SpringBootTest(
        classes = TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "firefly.security.bff.permit-matchers[0]=/public/**"
        })
@AutoConfigureWebTestClient
class BffSecurityAutoConfigurationTest {

    @Autowired
    private WebTestClient client;

    @Test
    void unauthenticatedRequestReturns401ForXhr() {
        client.get().uri("/anything")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void unauthenticatedBrowserNavigationRedirectsToLogin() {
        client.get().uri("/anything")
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .exchange()
                .expectStatus().isFound()
                .expectHeader().valueEquals(HttpHeaders.LOCATION, "/oauth2/authorization/idp");
    }

    @Test
    void loginEndpointRedirectsToIdpAuthorizationEndpoint() {
        client.get().uri("/oauth2/authorization/idp")
                .exchange()
                .expectStatus().isFound()
                .expectHeader().value(HttpHeaders.LOCATION, location -> assertThat(location).startsWith(TestApp.AUTH_URI));
    }

    @Test
    void permitMatchedPathBypassesAuthentication() {
        // /public/** is permitted; with no handler it 404s — proving it passed security (not a 401).
        client.get().uri("/public/ping")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isNotFound();
    }
}
