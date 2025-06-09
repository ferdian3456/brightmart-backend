CREATE TABLE IF NOT EXISTS users(
    id char(36) PRIMARY KEY,
    username varchar(22) UNIQUE NOT NULL,
    email varchar(80) UNIQUE NOT NULL,
    phone_number varchar(15) UNIQUE,
    auth_provider text NOT NULL DEFAULT 'local',
    provider_user_id text,
    is_verified boolean DEFAULT FALSE,
    password varchar(60) NOT NULL,
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL
)