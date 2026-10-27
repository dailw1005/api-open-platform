package com.apiproject.gateway.security;

import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RouteTemplateExpander {

    private static final Pattern PARAMETER =
            Pattern.compile("\\{([A-Za-z][A-Za-z0-9_]{0,63})}");
    private static final Pattern SAFE_VALUE =
            Pattern.compile("^[A-Za-z0-9._~-]{1,256}$");

    private RouteTemplateExpander() {
    }

    public static String expand(
            String template,
            Map<String, String> parameters
    ) {
        Objects.requireNonNull(template, "template");
        Objects.requireNonNull(parameters, "parameters");
        Matcher matcher = PARAMETER.matcher(template);
        StringBuilder expanded = new StringBuilder(template.length());
        int cursor = 0;
        while (matcher.find()) {
            expanded.append(template, cursor, matcher.start());
            String name = matcher.group(1);
            String value = parameters.get(name);
            if (value == null || !SAFE_VALUE.matcher(value).matches()) {
                throw new IllegalArgumentException(
                        "route parameter is missing or unsafe: " + name
                );
            }
            expanded.append(value);
            cursor = matcher.end();
        }
        expanded.append(template, cursor, template.length());
        String result = expanded.toString();
        if (result.indexOf('{') >= 0 || result.indexOf('}') >= 0) {
            throw new IllegalArgumentException(
                    "route template contains an invalid parameter"
            );
        }
        return result;
    }
}
