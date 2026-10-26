package com.apiproject.gateway.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class HmacCanonicalizer {

    private static final String VERSION_PREFIX = "AK-HMAC-V1";
    private static final Set<String> ALLOWED_METHODS =
            Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> ALLOWED_CONTENT_TYPES =
            Set.of("application/json", "application/x-www-form-urlencoded", "text/plain");
    private static final Pattern APP_KEY_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
    private static final Pattern NONCE_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]{16,128}$");
    private static final int MIN_SECRET_BYTES = 32;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HmacCanonicalizer() {
    }

    public static HmacCanonicalizer createDefault() {
        return new HmacCanonicalizer();
    }

    public HmacCanonicalResult canonicalize(
            HmacCanonicalRequest request,
            byte[] secret
    ) {
        if (secret == null || secret.length < MIN_SECRET_BYTES) {
            throw invalid("INVALID_SECRET", "HMAC secret must contain at least 256 bits");
        }

        String appKey = normalizeAppKey(request.appKey());
        String method = normalizeMethod(request.method());
        String host = normalizeHost(request.host());
        String path = canonicalizePath(request.rawPath());
        String query = canonicalizeQuery(request.rawQuery());
        byte[] body = request.body();
        String contentType = normalizeContentType(request.contentType(), body.length);
        String nonce = normalizeNonce(request.nonce());
        if (request.timestampSeconds() < 0) {
            throw invalid("INVALID_TIMESTAMP", "Timestamp must be non-negative");
        }

        String canonical = String.join(
                "\n",
                VERSION_PREFIX,
                appKey,
                host,
                method,
                path,
                query,
                contentType,
                Long.toString(request.timestampSeconds()),
                nonce,
                sha256Hex(body)
        );
        return new HmacCanonicalResult(canonical, hmacSha256Hex(canonical, secret));
    }

    private String normalizeAppKey(String appKey) {
        if (appKey == null || !APP_KEY_PATTERN.matcher(appKey).matches()) {
            throw invalid("INVALID_APP_KEY", "AppKey format is invalid");
        }
        return appKey;
    }

    private String normalizeMethod(String method) {
        if (method == null
                || method.isBlank()
                || !method.equals(method.trim())) {
            throw invalid("INVALID_METHOD", "HTTP method is required");
        }
        String normalized = method.trim().toUpperCase(Locale.ROOT);
        if (!ALLOWED_METHODS.contains(normalized)) {
            throw invalid("INVALID_METHOD", "HTTP method is not supported");
        }
        return normalized;
    }

    private String normalizeHost(String host) {
        if (host == null
                || host.isBlank()
                || !host.equals(host.trim())
                || host.chars().anyMatch(codePoint ->
                        codePoint <= 0x20
                                || codePoint == 0x7f
                                || codePoint > 0x7f)
                || host.indexOf('@') >= 0
                || host.indexOf('/') >= 0
                || host.indexOf('\\') >= 0) {
            throw invalid("INVALID_HOST", "Host format is invalid");
        }

        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("[")) {
            int closingBracket = normalized.indexOf(']');
            if (closingBracket < 0) {
                throw invalid("INVALID_HOST", "IPv6 host is invalid");
            }
            String ipv6 = normalized.substring(0, closingBracket + 1);
            String remainder = normalized.substring(closingBracket + 1);
            if (!ipv6.matches("^\\[[0-9a-f:.]+\\]$")) {
                throw invalid("INVALID_HOST", "IPv6 host is invalid");
            }
            if (remainder.isEmpty()) {
                return ipv6;
            }
            if (!remainder.startsWith(":")) {
                throw invalid("INVALID_HOST", "Host port is invalid");
            }
            return appendNonDefaultPort(ipv6, remainder.substring(1));
        }

        int firstColon = normalized.indexOf(':');
        int lastColon = normalized.lastIndexOf(':');
        if (firstColon != lastColon) {
            throw invalid("INVALID_HOST", "Unbracketed IPv6 host is invalid");
        }
        String hostName = firstColon < 0 ? normalized : normalized.substring(0, firstColon);
        if (!isValidHostName(hostName)) {
            throw invalid("INVALID_HOST", "Host name is invalid");
        }
        if (firstColon < 0) {
            return hostName;
        }
        return appendNonDefaultPort(hostName, normalized.substring(firstColon + 1));
    }

    private boolean isValidHostName(String hostName) {
        if (hostName.isEmpty() || hostName.length() > 253) {
            return false;
        }
        String[] labels = hostName.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty()
                    || label.length() > 63
                    || !label.matches("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")) {
                return false;
            }
        }
        return true;
    }

    private String appendNonDefaultPort(String host, String rawPort) {
        int port;
        try {
            port = Integer.parseInt(rawPort);
        } catch (NumberFormatException exception) {
            throw invalid("INVALID_HOST", "Host port is invalid");
        }
        if (port < 1 || port > 65535) {
            throw invalid("INVALID_HOST", "Host port is out of range");
        }
        return port == 80 || port == 443 ? host : host + ":" + port;
    }

    private String canonicalizePath(String rawPath) {
        if (rawPath == null
                || !rawPath.startsWith("/")
                || rawPath.contains("//")
                || rawPath.indexOf('?') >= 0
                || rawPath.indexOf('#') >= 0
                || rawPath.indexOf('\\') >= 0
                || rawPath.chars().anyMatch(codePoint ->
                        Character.isWhitespace(codePoint)
                                || Character.isISOControl(codePoint))) {
            throw invalid("INVALID_PATH", "Path format is invalid");
        }

        String[] segments = rawPath.split("/", -1);
        StringBuilder canonical = new StringBuilder(rawPath.length());
        for (int index = 0; index < segments.length; index++) {
            if (index > 0) {
                canonical.append('/');
            }
            if (segments[index].isEmpty()) {
                continue;
            }
            String decoded = percentDecodeUtf8(segments[index], "INVALID_PATH");
            if (".".equals(decoded) || "..".equals(decoded)) {
                throw invalid("INVALID_PATH", "Dot path segments are not allowed");
            }
            canonical.append(canonicalizePathSegment(segments[index]));
        }
        return canonical.toString();
    }

    private String canonicalizePathSegment(String segment) {
        StringBuilder canonical = new StringBuilder(segment.length());
        for (int offset = 0; offset < segment.length(); ) {
            int codePoint = segment.codePointAt(offset);
            offset += Character.charCount(codePoint);
            if (codePoint == '%') {
                int decoded = parsePercentTriplet(segment, offset - 1, "INVALID_PATH");
                offset += 2;
                if (decoded == '/' || decoded == '\\') {
                    throw invalid("INVALID_PATH", "Encoded path separators are not allowed");
                }
                if (decoded < 0x20 || decoded == 0x7f) {
                    throw invalid("INVALID_PATH", "Encoded path control characters are not allowed");
                }
                if (isUnreserved(decoded)) {
                    canonical.append((char) decoded);
                } else {
                    appendPercentByte(canonical, decoded);
                }
                continue;
            }
            if (codePoint <= 0x7f) {
                if (!isPathCharacter(codePoint)) {
                    throw invalid("INVALID_PATH", "Path contains an invalid character");
                }
                canonical.append((char) codePoint);
                continue;
            }
            byte[] encoded = new String(Character.toChars(codePoint))
                    .getBytes(StandardCharsets.UTF_8);
            for (byte value : encoded) {
                appendPercentByte(canonical, value & 0xff);
            }
        }
        return canonical.toString();
    }

    private String canonicalizeQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return "";
        }
        if (rawQuery.indexOf('+') >= 0
                || rawQuery.indexOf('#') >= 0
                || rawQuery.chars().anyMatch(codePoint ->
                        Character.isWhitespace(codePoint)
                                || Character.isISOControl(codePoint))) {
            throw invalid("INVALID_QUERY", "Query contains an invalid character");
        }

        String[] rawPairs = rawQuery.split("&", -1);
        List<QueryPair> pairs = new ArrayList<>(rawPairs.length);
        for (String rawPair : rawPairs) {
            if (rawPair.isEmpty()) {
                throw invalid("INVALID_QUERY", "Empty query pair is not allowed");
            }
            int separator = rawPair.indexOf('=');
            String rawName = separator < 0 ? rawPair : rawPair.substring(0, separator);
            String rawValue = separator < 0 ? "" : rawPair.substring(separator + 1);
            if (rawName.isEmpty()) {
                throw invalid("INVALID_QUERY", "Query name must not be empty");
            }
            String decodedName = percentDecodeUtf8(rawName, "INVALID_QUERY");
            String decodedValue = percentDecodeUtf8(rawValue, "INVALID_QUERY");
            rejectControlCharacters(decodedName, "INVALID_QUERY");
            rejectControlCharacters(decodedValue, "INVALID_QUERY");
            pairs.add(new QueryPair(
                    encodeRfc3986(decodedName),
                    encodeRfc3986(decodedValue)
            ));
        }
        pairs.sort(Comparator.comparing(QueryPair::name).thenComparing(QueryPair::value));
        return pairs.stream()
                .map(pair -> pair.name() + "=" + pair.value())
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
    }

    private String normalizeContentType(String contentType, int bodyLength) {
        if (contentType == null || contentType.isBlank()) {
            if (bodyLength > 0) {
                throw invalid("CONTENT_TYPE_REQUIRED", "Content-Type is required for a body");
            }
            return "";
        }
        int parameterSeparator = contentType.indexOf(';');
        String mediaType = (parameterSeparator < 0
                ? contentType
                : contentType.substring(0, parameterSeparator))
                .trim()
                .toLowerCase(Locale.ROOT);
        if (!ALLOWED_CONTENT_TYPES.contains(mediaType)) {
            throw invalid("UNSUPPORTED_CONTENT_TYPE", "Content-Type is not supported");
        }
        return mediaType;
    }

    private String normalizeNonce(String nonce) {
        if (nonce == null || !NONCE_PATTERN.matcher(nonce).matches()) {
            throw invalid("INVALID_NONCE", "Nonce format is invalid");
        }
        return nonce;
    }

    private String percentDecodeUtf8(String value, String errorCode) {
        ByteArrayOutputStream decoded = new ByteArrayOutputStream(value.length());
        for (int offset = 0; offset < value.length(); ) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            if (codePoint == '%') {
                decoded.write(parsePercentTriplet(value, offset - 1, errorCode));
                offset += 2;
                continue;
            }
            byte[] bytes = new String(Character.toChars(codePoint))
                    .getBytes(StandardCharsets.UTF_8);
            decoded.writeBytes(bytes);
        }
        try {
            CharBuffer characters = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded.toByteArray()));
            return characters.toString();
        } catch (CharacterCodingException exception) {
            throw invalid(errorCode, "Value is not valid UTF-8");
        }
    }

    private int parsePercentTriplet(String value, int percentIndex, String errorCode) {
        if (percentIndex + 2 >= value.length()) {
            throw invalid(errorCode, "Percent-encoding is incomplete");
        }
        int high = Character.digit(value.charAt(percentIndex + 1), 16);
        int low = Character.digit(value.charAt(percentIndex + 2), 16);
        if (high < 0 || low < 0) {
            throw invalid(errorCode, "Percent-encoding is invalid");
        }
        return (high << 4) | low;
    }

    private void rejectControlCharacters(String value, String errorCode) {
        if (value.chars().anyMatch(codePoint ->
                codePoint < 0x20 || codePoint == 0x7f)) {
            throw invalid(errorCode, "Control characters are not allowed");
        }
    }

    private String encodeRfc3986(String value) {
        StringBuilder encoded = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            if (isUnreserved(codePoint)) {
                encoded.append((char) codePoint);
            } else {
                byte[] bytes = new String(Character.toChars(codePoint))
                        .getBytes(StandardCharsets.UTF_8);
                for (byte valueByte : bytes) {
                    appendPercentByte(encoded, valueByte & 0xff);
                }
            }
        });
        return encoded.toString();
    }

    private boolean isPathCharacter(int codePoint) {
        return isUnreserved(codePoint)
                || isSubDelimiter(codePoint)
                || codePoint == ':'
                || codePoint == '@';
    }

    private boolean isUnreserved(int codePoint) {
        return (codePoint >= 'a' && codePoint <= 'z')
                || (codePoint >= 'A' && codePoint <= 'Z')
                || (codePoint >= '0' && codePoint <= '9')
                || codePoint == '-'
                || codePoint == '.'
                || codePoint == '_'
                || codePoint == '~';
    }

    private boolean isSubDelimiter(int codePoint) {
        return switch (codePoint) {
            case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' -> true;
            default -> false;
        };
    }

    private void appendPercentByte(StringBuilder target, int value) {
        target.append('%');
        target.append(Character.toUpperCase(HEX[(value >>> 4) & 0x0f]));
        target.append(Character.toUpperCase(HEX[value & 0x0f]));
    }

    private String sha256Hex(byte[] value) {
        try {
            return toHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private String hmacSha256Hex(String canonical, byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return toHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HmacSHA256 is unavailable", exception);
        }
    }

    private String toHex(byte[] bytes) {
        char[] encoded = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            encoded[index * 2] = HEX[value >>> 4];
            encoded[index * 2 + 1] = HEX[value & 0x0f];
        }
        return new String(encoded);
    }

    private HmacCanonicalizationException invalid(String code, String message) {
        return new HmacCanonicalizationException(code, message);
    }

    private record QueryPair(String name, String value) {
    }
}
