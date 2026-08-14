package com.monokek.identity.web.dto;

import java.util.Map;

/** Backs GET /internal/users?ids=... — the HTTP equivalent of the old in-process UserDirectory. */
public record UserNamesResponse(Map<Long, String> names) {
}
