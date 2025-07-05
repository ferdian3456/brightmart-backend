CREATE TABLE admins IF NOT EXISTS(
    id char(36) PRIMARY KEY,
    username varchar(100) UNIQUE NOT NULL
    email varchar(80) UNIQUE NOT NULL,
    password varchar(60) NOT NULL,
    role varchar(20) NOT NULL CHECK (role IN ('admin','superadmin')),
    created_by char(36),
    is_active boolean NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (created_by) REFERENCES admins(id)
)