CREATE TABLE IF NOT EXISTS banners(
    id serial PRIMARY KEY,
    name char(36) NOT NULL,
    created_by char(36) NOT NULL,
    last_updated_by char(36) NOT NULL,
    created_at timestamp,
    updated_at timestamp,
    FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE CASCADE
)