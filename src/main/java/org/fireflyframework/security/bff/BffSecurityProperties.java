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

    /**
     * Paths exempt from CSRF protection. For server-to-server callbacks that carry their own signed
     * proof instead of a browser session cookie (e.g. an OIDC <em>back-channel logout</em> endpoint,
     * which Keycloak POSTs a signed {@code logout_token} to, with no cookie and no CSRF header). These
     * paths must also be listed in {@link #permitMatchers}. Empty by default (nothing exempt).
     */
    private List<String> csrfExemptMatchers = new ArrayList<>();

    /** Where to send the browser after an RP-initiated logout completes at the IdP. */
    private String postLogoutRedirectUri = "{baseUrl}";

    /**
     * When true, {@code POST /logout} answers fetch/XHR callers with {@code 200} +
     * {@code {"logoutUrl":...}} instead of a {@code 302}, so a SPA can drive the navigation to the IdP
     * end-session endpoint itself. Browser document loads still get the {@code 302}. Opt-in: default
     * {@code false} keeps the classic redirect for every caller.
     */
    private boolean xhrAwareLogout = false;

    /**
     * When true, a dead-session token failure raised by the gateway {@code TokenRelay} (expired/revoked
     * refresh token, or no authorized client) is turned into a clean {@code 401} +
     * {@code {"loginUrl":...}} for XHR / {@code 302}-to-login for browsers, with session invalidation,
     * instead of an opaque {@code 500}. Opt-in: default {@code false}.
     */
    private boolean refreshFailure401 = false;

    /**
     * When true, a filter subscribes to the deferred CSRF token on every request so the
     * {@code XSRF-TOKEN} cookie is actually delivered to the browser. Needed for a SPA to echo the
     * token back on state-changing requests (e.g. {@code POST /logout}); without it the token stays
     * deferred and the cookie is never emitted. Opt-in: default {@code false}.
     */
    private boolean csrfCookie = false;

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

    public List<String> getCsrfExemptMatchers() {
        return csrfExemptMatchers;
    }

    public void setCsrfExemptMatchers(List<String> csrfExemptMatchers) {
        this.csrfExemptMatchers = csrfExemptMatchers;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }

    public boolean isXhrAwareLogout() {
        return xhrAwareLogout;
    }

    public void setXhrAwareLogout(boolean xhrAwareLogout) {
        this.xhrAwareLogout = xhrAwareLogout;
    }

    public boolean isRefreshFailure401() {
        return refreshFailure401;
    }

    public void setRefreshFailure401(boolean refreshFailure401) {
        this.refreshFailure401 = refreshFailure401;
    }

    public boolean isCsrfCookie() {
        return csrfCookie;
    }

    public void setCsrfCookie(boolean csrfCookie) {
        this.csrfCookie = csrfCookie;
    }
}
