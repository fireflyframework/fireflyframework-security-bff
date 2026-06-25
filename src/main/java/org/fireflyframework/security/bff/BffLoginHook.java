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

import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Opt-in extension point invoked <strong>once per successful login</strong>, in the oauth2Login success
 * handler, before the post-login redirect. The canonical use is just-in-time (JIT) reconciliation of a
 * local user projection from the validated token (e.g. BFF &rarr; {@code domain} &rarr; {@code core},
 * never BFF &rarr; {@code core} directly).
 *
 * <p>Contribute any number of {@code BffLoginHook} beans; they run in {@code @Order} sequence. The login
 * is <strong>fail-closed</strong>: if a hook errors, the login does not complete (no redirect) and the
 * request fails — a half-provisioned session is never served. Hooks run after the tokens are stored in
 * the session, so {@code authentication} carries the OIDC principal/claims.</p>
 */
public interface BffLoginHook {

    /**
     * @param authentication the successful authentication (typically an OIDC principal carrying the claims)
     * @param exchange       the current exchange
     * @return completion; an error fails the login (fail-closed)
     */
    Mono<Void> onLogin(Authentication authentication, ServerWebExchange exchange);
}
