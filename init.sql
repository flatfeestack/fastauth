CREATE TABLE IF NOT EXISTS auth (
	email VARCHAR(64) PRIMARY KEY,
    inviteEmail VARCHAR(64),
	password VARCHAR(49),
	refreshToken VARCHAR(32) NOT NULL,
	emailToken VARCHAR(32),
	forgetEmailToken VARCHAR(32),
    sms VARCHAR(16),
    smsVerified INT DEFAULT 0,
	totp VARCHAR(64),
    totpVerified INT DEFAULT 0,
	errorCount INT DEFAULT 0,
    meta TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit (
    email TEXT,
    action TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX emailIndex ON audit (email);
