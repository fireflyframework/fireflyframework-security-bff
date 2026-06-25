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

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.DelegatingServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import reactor.core.publisher.Flux;

import java.util.List;

import java.util.Set;

/**
 * Secure-by-default token-handler BFF.
 *
 * <p>Turns a reactive application (typically a Spring Cloud Gateway) into the confidential OAuth
 * client that runs Authorization Code + PKCE server-side, keeps the user's tokens in the server-side
 * session (Redis-backed via Spring Session in production), hands the browser only an opaque
 * {@code __Host-} session cookie, and exposes a per-user, session-bound
 * {@link ReactiveOAuth2AuthorizedClientManager} so a gateway {@code TokenRelay} can attach the
 * logged-in user's access token downstream. The browser never sees a token.</p>
 *
 * <p>Spring-Cloud-Gateway-agnostic: this contributes only the security chain and the session-bound
 * manager. Routing, the {@code TokenRelay} filter and trusted-header stripping stay in the consuming
 * application. Every bean is {@link ConditionalOnMissingBean}, so an application can override any
 * single piece. The framework's {@code security-oauth2-client} module is intentionally not used here:
 * its manager is service/M2M-oriented and would hijack the per-user relay.</p>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ServerHttpSecurity.class, ReactiveClientRegistrationRepository.class})
@EnableConfigurationProperties(BffSecurityProperties.class)
public class BffSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecurityWebFilterChain bffSecurityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveClientRegistrationRepository clientRegistrations,
            BffSecurityProperties properties,
            ObjectProvider<BffLoginHook> loginHooks) {

        List<BffLoginHook> hooks = loginHooks.orderedStream().toList();

        http
                .authorizeExchange(exchanges -> {
                    if (!properties.getPermitMatchers().isEmpty()) {
                        exchanges.pathMatchers(properties.getPermitMatchers().toArray(String[]::new)).permitAll();
                    }
                    exchanges.anyExchange().authenticated();
                })
                // Authorization Code + PKCE, server-side. Tokens + principal land in the WebSession
                // (Redis-backed via Spring Session) — never in the browser. PKCE is forced explicitly:
                // Spring enables it automatically only for public clients, but a token-handler BFF is a
                // confidential client and must still send code_challenge (defence in depth; required when
                // the IdP enforces PKCE).
                .oauth2Login(login -> {
                    login.authorizationRequestResolver(pkceAuthorizationRequestResolver(clientRegistrations));
                    // Opt-in post-login hooks (e.g. JIT user reconciliation): run once per login, fail-closed,
                    // before the redirect. With no hooks, Spring's default success handling is left untouched.
                    if (!hooks.isEmpty()) {
                        login.authenticationSuccessHandler(loginSuccessHandler(hooks));
                    }
                })
                // Browser-facing cookie auth needs CSRF; XSRF-TOKEN is readable so the SPA can echo it.
                .csrf(csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()))
                // RP-initiated logout: clear the session and redirect to the IdP end-session endpoint.
                // (OIDC back-channel logout is wired by the consuming app / a later iteration.)
                .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrations, properties)))
                // 401 for XHR/API (so the SPA reacts), redirect-to-login only for browser document loads.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(browserAwareEntryPoint(properties)));

        return http.build();
    }

    /**
     * Per-user, session-bound authorized-client manager. A gateway {@code TokenRelay} filter uses this
     * bean to attach the logged-in user's access token to downstream calls; it reads the token from the
     * {@link ServerOAuth2AuthorizedClientRepository} (WebSession/Redis), not from an M2M store.
     */
    @Bean
    @ConditionalOnMissingBean
    public ReactiveOAuth2AuthorizedClientManager bffAuthorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrations,
            ServerOAuth2AuthorizedClientRepository authorizedClients) {

        ReactiveOAuth2AuthorizedClientProvider provider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();

        DefaultReactiveOAuth2AuthorizedClientManager manager =
                new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrations, authorizedClients);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    /**
     * Authorization-request resolver that always adds PKCE ({@code code_challenge}, S256). Spring only
     * enables PKCE automatically for public clients; a confidential token-handler BFF must opt in.
     */
    private ServerOAuth2AuthorizationRequestResolver pkceAuthorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrations) {
        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrations);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    /**
     * Runs the contributed {@link BffLoginHook}s once (in order), then performs the standard post-login
     * redirect. A hook error propagates (fail-closed): the redirect is skipped and the login fails rather
     * than serving a half-provisioned session.
     */
    private ServerAuthenticationSuccessHandler loginSuccessHandler(List<BffLoginHook> hooks) {
        ServerAuthenticationSuccessHandler runHooks = (webFilterExchange, authentication) ->
                Flux.fromIterable(hooks)
                        .concatMap(hook -> hook.onLogin(authentication, webFilterExchange.getExchange()))
                        .then();
        return new DelegatingServerAuthenticationSuccessHandler(runHooks, new RedirectServerAuthenticationSuccessHandler());
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
            ReactiveClientRegistrationRepository clientRegistrations, BffSecurityProperties properties) {
        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrations);
        handler.setPostLogoutRedirectUri(properties.getPostLogoutRedirectUri());
        return handler;
    }

    private ServerAuthenticationEntryPoint browserAwareEntryPoint(BffSecurityProperties properties) {
        // A browser document request (Accept: text/html) gets redirected to start the login; everything
        // else (XHR/fetch from the SPA) gets a 401 so it can consciously trigger the login navigation.
        MediaTypeServerWebExchangeMatcher htmlMatcher = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
        htmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));

        RedirectServerAuthenticationEntryPoint redirect =
                new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/" + properties.getRegistrationId());
        HttpStatusServerEntryPoint unauthorized = new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED);

        DelegatingServerAuthenticationEntryPoint delegating = new DelegatingServerAuthenticationEntryPoint(
                new DelegatingServerAuthenticationEntryPoint.DelegateEntry(htmlMatcher, redirect));
        delegating.setDefaultEntryPoint(unauthorized);
        return delegating;
    }
}
