DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
	id BLOB NOT NULL DEFAULT(randomblob(16)) PRIMARY KEY,
	email TEXT NOT NULL,
	sms TEXT,
	role TEXT NOT NULL,
	password BLOB NOT NULL,
	salt BLOB NOT NULL,
	refreshToken TEXT NOT NULL,
	emailToken TEXT,
	forgetEmailToken TEXT,
	totp TEXT,
	lang TEXT DEFAULT 'en',
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	emailSent TIMESTAMP,
	emailVerified TIMESTAMP,
	smsVerified TIMESTAMP,
	totpVerified TIMESTAMP,
	forgetEmail TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email
    ON users(email);

INSERT INTO users (id, email, sms, role, password, salt, refreshToken, emailToken, forgetEmailToken, totp, lang, created, emailSent, emailVerified, smsVerified, totpVerified, forgetEmail) VALUES (X'8EA4FCFA4A7664A541EAD722AE1A1F92', 'tom@test.ch', null, 'USR', X'0A139279851C25AACB8E4A8206FC8826B1268C661D0D64750E04ADD13CE4109B', X'7E37E2DC137E985C4F445DE008BF270C', X'608caa5d93cac281a29cbee0d134a724', null, null, null, 'en', '2020-09-14 16:35:15', '2020-09-14 16:35:15', '2020-09-14 16:35:15', null, null, null);
