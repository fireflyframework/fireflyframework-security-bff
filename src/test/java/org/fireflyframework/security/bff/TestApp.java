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

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Minimal reactive app for the autoconfiguration tests, with a STATIC (non-discovery) OAuth client
 * registration so the context starts without a live IdP.
 */
@SpringBootApplication
class TestApp {

    static final String AUTH_URI = "https://idp.test/realms/idp/protocol/openid-connect/auth";

    @Bean
    ReactiveClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration idp = ClientRegistration.withRegistrationId("idp")
                .clientId("test-bff")
                .clientSecret("test-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile")
                .authorizationUri(AUTH_URI)
                .tokenUri("https://idp.test/realms/idp/protocol/openid-connect/token")
                .jwkSetUri("https://idp.test/realms/idp/protocol/openid-connect/certs")
                .userInfoUri("https://idp.test/realms/idp/protocol/openid-connect/userinfo")
                .userNameAttributeName("sub")
                .clientName("idp")
                .build();
        return new InMemoryReactiveClientRegistrationRepository(idp);
    }
}
