CREATE TABLE IF NOT EXISTS sub_categories(
    id serial PRIMARY KEY,
    name char(13) NOT NULL,
    category_id int NOT NULL,
    created_by char(36) NOT NULL,
    last_updated_by char(36) NOT NULL,
    created_at timestamp,
    updated_at timestamp,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE CASCADE
)