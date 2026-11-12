package com.monokek.identity.security;

import com.monokek.identity.common.ApiException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AttemptLimiterTest {

    private static final Duration WINDOW = Duration.ofMinutes(5);

    private final AttemptLimiter limiter = new AttemptLimiter();

    @Test
    void locksOutOnceMaxFailuresReached() {
        for (int i = 0; i < 3; i++) {
            limiter.check("k", 3, WINDOW);
            limiter.recordFailure("k", WINDOW);
        }
        ApiException ex = assertThrows(ApiException.class, () -> limiter.check("k", 3, WINDOW));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, ex.getStatus());
    }

    @Test
    void successResetsTheCounter() {
        limiter.recordFailure("k", WINDOW);
        limiter.recordFailure("k", WINDOW);
        limiter.reset("k");
        limiter.recordFailure("k", WINDOW);
        assertDoesNotThrow(() -> limiter.check("k", 3, WINDOW));
    }

    @Test
    void failuresOutsideTheWindowAreForgotten() throws InterruptedException {
        Duration tiny = Duration.ofMillis(30);
        limiter.recordFailure("k", tiny);
        limiter.recordFailure("k", tiny);
        Thread.sleep(60);
        assertDoesNotThrow(() -> limiter.check("k", 2, tiny));
    }

    @Test
    void keysAreIndependentAndCaseInsensitive() {
        limiter.recordFailure("A@x.com", WINDOW);
        limiter.recordFailure("a@x.com", WINDOW);
        assertThrows(ApiException.class, () -> limiter.check("A@X.COM", 2, WINDOW));
        assertDoesNotThrow(() -> limiter.check("other@x.com", 2, WINDOW));
    }
}
