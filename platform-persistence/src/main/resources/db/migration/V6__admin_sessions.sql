ALTER TABLE iam_user
    ADD COLUMN display_name VARCHAR(100);

UPDATE iam_user
SET display_name = COALESCE(
    NULLIF(left(split_part(email, '@', 1), 100), ''),
    'User'
);

ALTER TABLE iam_user
    ALTER COLUMN display_name SET NOT NULL,
    ALTER COLUMN display_name SET DEFAULT 'User',
    ADD CONSTRAINT chk_iam_user_display_name
        CHECK (length(display_name) BETWEEN 1 AND 100);

CREATE TABLE iam_session (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES iam_user(id),
    csrf_token_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chk_iam_session_token_hash
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_iam_session_csrf_hash
        CHECK (csrf_token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_iam_session_lifetime
        CHECK (expires_at > created_at),
    CONSTRAINT chk_iam_session_revoked_at
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX idx_iam_session_user_active
    ON iam_session (user_id, expires_at DESC)
    WHERE revoked_at IS NULL;
