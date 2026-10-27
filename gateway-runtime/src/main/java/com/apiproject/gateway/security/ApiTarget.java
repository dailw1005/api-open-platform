package com.apiproject.gateway.security;

import java.net.URI;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public record ApiTarget(
        URI baseUri,
        String method,
        String pathTemplate,
        Duration timeout
) {

    private static final Set<String> ALLOWED_METHODS =
            Set.of("GET", "POST", "PUT", "PATCH", "DELETE");

    public ApiTarget {
        Objects.requireNonNull(baseUri, "baseUri");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(pathTemplate, "pathTemplate");
        Objects.requireNonNull(timeout, "timeout");
        if (!"https".equalsIgnoreCase(baseUri.getScheme())
                || baseUri.getHost() == null
                || baseUri.getUserInfo() != null
                || baseUri.getRawQuery() != null
                || baseUri.getRawFragment() != null
                || unsafePath(baseUri.getRawPath())
                || unsafeHost(baseUri.getHost())) {
            throw new IllegalArgumentException("upstream base URI is unsafe");
        }
        String normalizedMethod = method.toUpperCase(Locale.ROOT);
        if (!ALLOWED_METHODS.contains(normalizedMethod)) {
            throw new IllegalArgumentException("upstream method is invalid");
        }
        if (!pathTemplate.startsWith("/")
                || pathTemplate.contains("//")
                || pathTemplate.contains("?")
                || pathTemplate.contains("#")) {
            throw new IllegalArgumentException(
                    "upstream path template is invalid"
            );
        }
        if (timeout.isNegative()
                || timeout.isZero()
                || timeout.toMillis() > 30_000) {
            throw new IllegalArgumentException("upstream timeout is invalid");
        }
        method = normalizedMethod;
    }

    private static boolean unsafeHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(normalized) || normalized.endsWith(".localhost")) {
            return true;
        }
        if (!isIpLiteral(normalized)) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(normalized);
            if (address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()
                    || address.isMulticastAddress()) {
                return true;
            }
            byte[] bytes = address.getAddress();
            if (bytes.length == 4) {
                int first = bytes[0] & 0xff;
                int second = bytes[1] & 0xff;
                return first == 0
                        || (first == 100 && second >= 64 && second <= 127)
                        || (first == 192 && second == 0)
                        || (first == 198
                            && (second == 18 || second == 19));
            }
            return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
        } catch (UnknownHostException exception) {
            return true;
        }
    }

    private static boolean unsafePath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String normalized = path.toLowerCase(Locale.ROOT);
        return normalized.contains("\\")
                || normalized.contains("//")
                || normalized.contains("%2e")
                || normalized.contains("%2f")
                || normalized.contains("%5c")
                || normalized.contains("/../")
                || normalized.endsWith("/..")
                || normalized.contains("/./")
                || normalized.endsWith("/.");
    }

    private static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0
                || host.matches("^[0-9]{1,3}(?:\\.[0-9]{1,3}){3}$");
    }
}
