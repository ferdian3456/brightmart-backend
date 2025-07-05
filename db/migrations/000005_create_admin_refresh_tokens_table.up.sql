CREATE TABLE IF NOT EXISTS admin_refresh_tokens(
    id serial PRIMARY KEY,
    user_id char(36) NOT NULL,
    hashed_refresh_token char(64) NOT NULL,
    status varchar(10)  NOT NULL DEFAULT 'Valid',
    created_at timestamp NOT NULL,
    expired_at timestamp NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)