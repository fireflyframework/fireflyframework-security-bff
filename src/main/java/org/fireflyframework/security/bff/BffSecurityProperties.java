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

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the token-handler BFF security chain ({@link BffSecurityAutoConfiguration}).
 *
 * <p>Product-agnostic: the consuming BFF supplies its OAuth2 client registration, routes and public
 * paths; the framework supplies the secure-by-default chain.</p>
 */
@ConfigurationProperties("firefly.security.bff")
public class BffSecurityProperties {

    /**
     * Spring OAuth2 client {@code registration-id}. Neutral on purpose (not the provider name) so the
     * login endpoints are {@code /oauth2/authorization/<id>} and {@code /login/oauth2/code/<id>}.
     */
    private String registrationId = "idp";

    /**
     * Paths served without authentication (e.g. actuator, docs). The OAuth2 login endpoints are
     * handled by the login filter and need not be listed here.
     */
    private List<String> permitMatchers = new ArrayList<>();

    /** Where to send the browser after an RP-initiated logout completes at the IdP. */
    private String postLogoutRedirectUri = "{baseUrl}";

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public List<String> getPermitMatchers() {
        return permitMatchers;
    }

    public void setPermitMatchers(List<String> permitMatchers) {
        this.permitMatchers = permitMatchers;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }
}
