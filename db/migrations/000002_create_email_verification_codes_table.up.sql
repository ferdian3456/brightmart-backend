CREATE TABLE email_verification_codes (
   id SERIAL PRIMARY KEY,
   user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
   code_hash TEXT NOT NULL,
   expires_at TIMESTAMP NOT NULL,
   created_at TIMESTAMP DEFAULT NOW()
);
