-- DeepShield XAI Database Schema Configuration
-- Aiswarya M | Roll No: 727625MCA002
-- Dr. Mahalingam College Of Engineering And Technology
-- --------------------------------------------------------

CREATE DATABASE IF NOT EXISTS deepfake_db;
USE deepfake_db;

-- Table structure for table 'users'
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('user', 'admin') DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table structure for table 'analyses'
CREATE TABLE IF NOT EXISTS analyses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  filename VARCHAR(255) DEFAULT NULL,
  file_path VARCHAR(500) DEFAULT NULL,
  file_type ENUM('image', 'video', 'audio', 'url', 'webcam') DEFAULT 'image',
  verdict ENUM('FAKE', 'REAL', 'UNCERTAIN') NOT NULL,
  confidence FLOAT DEFAULT 0,
  cnn_score FLOAT DEFAULT 0,
  transformer_score FLOAT DEFAULT 0,
  frequency_score FLOAT DEFAULT 0,
  ensemble_score FLOAT DEFAULT 0,
  xai_data LONGTEXT DEFAULT NULL,
  processing_time FLOAT DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_verdict (verdict),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert an initial default admin profile for demonstration
-- Password is 'admin123' hashed with pbkdf2:sha256
INSERT IGNORE INTO users (id, username, email, password, role)
VALUES (1, 'Admin', 'admin@deepshield.com', 'pbkdf2:sha256:600000$P6Wv2e7X$0b90e96f1837bc4495c0c9397669ba4ce415fa9d150b07b8b2fc6eb664a7c29e', 'admin');
