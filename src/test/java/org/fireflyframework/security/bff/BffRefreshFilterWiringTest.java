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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the opt-in wiring of {@link BffRefreshTokenFailureWebFilter}: the bean exists only when
 * {@code firefly.security.bff.refresh-failure-401=true}, and is ordered at {@code -101}.
 */
class BffRefreshFilterWiringTest {

    @Nested
    @SpringBootTest(classes = TestApp.class)
    @TestPropertySource(properties = "firefly.security.bff.refresh-failure-401=true")
    class Enabled {
        @Autowired
        ObjectProvider<BffRefreshTokenFailureWebFilter> filter;

        @Test
        void beanIsRegisteredAndOrderedOutsideSecurityChain() {
            BffRefreshTokenFailureWebFilter bean = filter.getIfAvailable();
            assertThat(bean).isNotNull();
            assertThat(bean.getOrder()).isEqualTo(-101);
        }
    }

    @Nested
    @SpringBootTest(classes = TestApp.class)
    class DisabledByDefault {
        @Autowired
        ObjectProvider<BffRefreshTokenFailureWebFilter> filter;

        @Test
        void beanIsAbsentWhenPropertyNotSet() {
            assertThat(filter.getIfAvailable()).isNull();
        }
    }
}
