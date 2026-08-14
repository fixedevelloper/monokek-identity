package com.monokek.identity.common;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Same envelope shape as monokek-spring's com.monokek.common.ApiResponse, so existing clients are unaffected. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(String status, String message, T data, Object errors) {

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("success", null, data, null);
    }

    public static <T> ApiResponse<T> success(T data, String message) {
        return new ApiResponse<>("success", message, data, null);
    }

    public static <T> ApiResponse<T> message(String message) {
        return new ApiResponse<>("success", message, null, null);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>("error", message, null, null);
    }
}
