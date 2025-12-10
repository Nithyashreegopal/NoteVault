-- Create table for sharing entire notes pages (units)
CREATE TABLE IF NOT EXISTS page_share_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    unit_id INT NOT NULL,
    share_token VARCHAR(255) NOT NULL UNIQUE,
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX (share_token),
    INDEX (unit_id),
    INDEX (created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
