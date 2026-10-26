package com.apiproject.orchestration;

import java.util.List;
import java.util.Objects;

public record FlowValidationResult(List<FlowValidationIssue> issues) {
    public FlowValidationResult {
        issues = List.copyOf(Objects.requireNonNull(issues, "issues"));
    }

    public boolean valid() {
        return issues.isEmpty();
    }

    public boolean hasCode(String code) {
        return issues.stream().anyMatch(issue -> issue.code().equals(code));
    }
}
