CREATE TABLE IF NOT EXISTS auth (
	email VARCHAR(64) PRIMARY KEY,
	password VARCHAR(80),
	refresh_token VARCHAR(32) NOT NULL,
	email_token VARCHAR(32),
	forget_email_token VARCHAR(32),
	invite_token VARCHAR(32),
    sms VARCHAR(16),
    sms_verified TIMESTAMP,
	totp VARCHAR(64),
    totp_verified TIMESTAMP,
	error_count INT DEFAULT 0,
    meta_user VARCHAR(255),
    meta_system TEXT,
    created_at TIMESTAMP NOT NULL
);
