package com.monokek.identity.security;

import com.monokek.identity.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Counts <em>failed</em> credential checks per key (an email, a branch's PIN pad, a user id) in a
 * sliding window and locks the key out once {@code maxFailures} is reached — a legitimate user
 * who types the right secret is never slowed down, but guessing a password or a 4-digit PIN
 * (10 000 combinations) becomes impractical. In-memory on purpose: monokek-identity runs as a
 * single instance, and a restart clearing the counters only helps an attacker once per restart.
 */
@Component
public class AttemptLimiter {

    public static final int LOGIN_MAX_FAILURES = 5;
    public static final Duration LOGIN_WINDOW = Duration.ofMinutes(15);
    public static final int PIN_MAX_FAILURES = 10;
    public static final Duration PIN_WINDOW = Duration.ofMinutes(5);

    /** Beyond this many tracked keys, expired entries are purged so a key-spraying attacker can't grow the map forever. */
    private static final int PURGE_THRESHOLD = 10_000;

    private final ConcurrentHashMap<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

    /** Throws 429 if {@code key} already has {@code maxFailures} failures inside {@code window}. */
    public void check(String key, int maxFailures, Duration window) {
        Deque<Instant> attempts = failures.get(normalize(key));
        if (attempts == null) {
            return;
        }
        synchronized (attempts) {
            prune(attempts, window);
            if (attempts.size() >= maxFailures) {
                throw tooManyAttempts();
            }
        }
    }

    public void recordFailure(String key, Duration window) {
        if (failures.size() > PURGE_THRESHOLD) {
            failures.values().removeIf(attempts -> {
                synchronized (attempts) {
                    prune(attempts, window);
                    return attempts.isEmpty();
                }
            });
        }
        Deque<Instant> attempts = failures.computeIfAbsent(normalize(key), k -> new ArrayDeque<>());
        synchronized (attempts) {
            attempts.addLast(Instant.now());
        }
    }

    public void reset(String key) {
        failures.remove(normalize(key));
    }

    public static String loginKey(String email) {
        return "login:" + email;
    }

    public static String branchPinKey(Long branchId) {
        return "pin-branch:" + branchId;
    }

    public static String userPinKey(Long userId) {
        return "pin-user:" + userId;
    }

    public static String passwordChangeKey(Long userId) {
        return "pwd-user:" + userId;
    }

    public static ApiException tooManyAttempts() {
        return new ApiException(HttpStatus.TOO_MANY_REQUESTS, "Trop de tentatives, réessayez dans quelques minutes.");
    }

    private static void prune(Deque<Instant> attempts, Duration window) {
        Instant cutoff = Instant.now().minus(window);
        while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
            attempts.pollFirst();
        }
    }

    private static String normalize(String key) {
        return key == null ? "" : key.toLowerCase(Locale.ROOT);
    }
}
