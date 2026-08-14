package com.monokek.identity;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/** Backs @Async on HttpActivityNotifier — audit-log webhook calls never block a request thread. */
@Configuration
@EnableAsync
class AsyncConfig {
}
