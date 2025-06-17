CREATE TABLE email_verification_codes (
   id serial PRIMARY KEY,
   user_id char(36) NOT NULL,
   code_hash text NOT NULL,
   expires_at timestamp NOT NULL,
   created_at timestamp  NOT NULL,
   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
