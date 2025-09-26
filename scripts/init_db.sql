-- AI Phishing Detection System Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for system access
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email analysis results
CREATE TABLE email_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(255) NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    subject TEXT,
    body_text TEXT,
    body_html TEXT,
    received_date TIMESTAMP WITH TIME ZONE,
    
    -- Analysis scores
    overall_threat_score DECIMAL(5,4) NOT NULL,
    content_score DECIMAL(5,4) DEFAULT 0,
    url_score DECIMAL(5,4) DEFAULT 0,
    attachment_score DECIMAL(5,4) DEFAULT 0,
    header_score DECIMAL(5,4) DEFAULT 0,
    
    -- ML model predictions
    random_forest_score DECIMAL(5,4),
    svm_score DECIMAL(5,4),
    deep_learning_score DECIMAL(5,4),
    ensemble_prediction DECIMAL(5,4),
    
    -- Classification
    is_phishing BOOLEAN NOT NULL,
    confidence_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    threat_category VARCHAR(50), -- PHISHING, MALWARE, SPAM, LEGITIMATE
    
    -- Processing metadata
    analysis_duration_ms INTEGER,
    model_version VARCHAR(50),
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    CONSTRAINT unique_message_analysis UNIQUE(message_id)
);

-- URL analysis results
CREATE TABLE url_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_analysis_id UUID REFERENCES email_analyses(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    domain VARCHAR(255),
    
    -- Reputation scores
    virustotal_score DECIMAL(5,4),
    urlvoid_score DECIMAL(5,4),
    joe_sandbox_score DECIMAL(5,4),
    
    -- Analysis results
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_types TEXT[], -- Array of threat types
    reputation_category VARCHAR(50),
    
    -- Metadata
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Attachment analysis results
CREATE TABLE attachment_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_analysis_id UUID REFERENCES email_analyses(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    file_size INTEGER,
    mime_type VARCHAR(100),
    file_hash VARCHAR(64), -- SHA-256 hash
    
    -- YARA analysis
    yara_matches TEXT[], -- Array of matched rules
    yara_threat_score DECIMAL(5,4),
    
    -- Malware detection
    is_malware BOOLEAN DEFAULT FALSE,
    malware_family VARCHAR(100),
    
    -- Metadata
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email headers analysis
CREATE TABLE header_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_analysis_id UUID REFERENCES email_analyses(id) ON DELETE CASCADE,
    
    -- Authentication results
    spf_result VARCHAR(20), -- PASS, FAIL, NEUTRAL, NONE
    dkim_result VARCHAR(20),
    dmarc_result VARCHAR(20),
    
    -- IP analysis
    sender_ip INET,
    sender_country VARCHAR(2),
    sender_reputation_score DECIMAL(5,4),
    
    -- Routing analysis
    hop_count INTEGER,
    suspicious_routing BOOLEAN DEFAULT FALSE,
    timestamp_anomalies BOOLEAN DEFAULT FALSE,
    
    -- Overall header score
    header_authenticity_score DECIMAL(5,4),
    
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User monitoring and behavior tracking
CREATE TABLE user_monitoring (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_email VARCHAR(255) NOT NULL,
    subscription_id VARCHAR(255), -- Graph API subscription ID
    
    -- Monitoring settings
    is_active BOOLEAN DEFAULT TRUE,
    monitoring_level VARCHAR(20) DEFAULT 'STANDARD', -- BASIC, STANDARD, INTENSIVE
    
    -- Statistics
    emails_processed INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT unique_user_monitoring UNIQUE(user_email)
);

-- Quarantine management
CREATE TABLE quarantined_emails (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_analysis_id UUID REFERENCES email_analyses(id) ON DELETE CASCADE,
    user_email VARCHAR(255) NOT NULL,
    
    -- Quarantine details
    quarantine_reason TEXT NOT NULL,
    quarantine_folder VARCHAR(255), -- Graph API folder ID
    original_folder VARCHAR(255),
    
    -- Status
    status VARCHAR(20) DEFAULT 'QUARANTINED', -- QUARANTINED, RELEASED, DELETED
    reviewed_by VARCHAR(255),
    review_notes TEXT,
    
    -- Timestamps
    quarantined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- System performance metrics
CREATE TABLE performance_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4) NOT NULL,
    metric_unit VARCHAR(20),
    
    -- Context
    component VARCHAR(50), -- API, ML_MODEL, DATABASE, etc.
    additional_data JSONB,
    
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Model training history
CREATE TABLE model_training_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    
    -- Training metrics
    accuracy DECIMAL(5,4),
    precision_score DECIMAL(5,4),
    recall DECIMAL(5,4),
    f1_score DECIMAL(5,4),
    
    -- Training details
    training_samples INTEGER,
    validation_samples INTEGER,
    training_duration_minutes INTEGER,
    
    -- Model file path
    model_file_path VARCHAR(500),
    
    -- Status
    is_active BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_email_analyses_sender ON email_analyses(sender_email);
CREATE INDEX idx_email_analyses_recipient ON email_analyses(recipient_email);
CREATE INDEX idx_email_analyses_threat_score ON email_analyses(overall_threat_score DESC);
CREATE INDEX idx_email_analyses_processed_at ON email_analyses(processed_at DESC);
CREATE INDEX idx_email_analyses_is_phishing ON email_analyses(is_phishing);

CREATE INDEX idx_url_analyses_domain ON url_analyses(domain);
CREATE INDEX idx_url_analyses_malicious ON url_analyses(is_malicious);

CREATE INDEX idx_attachment_analyses_hash ON attachment_analyses(file_hash);
CREATE INDEX idx_attachment_analyses_malware ON attachment_analyses(is_malware);

CREATE INDEX idx_user_monitoring_email ON user_monitoring(user_email);
CREATE INDEX idx_user_monitoring_active ON user_monitoring(is_active);

CREATE INDEX idx_quarantined_status ON quarantined_emails(status);
CREATE INDEX idx_quarantined_user ON quarantined_emails(user_email);

CREATE INDEX idx_performance_metrics_name ON performance_metrics(metric_name);
CREATE INDEX idx_performance_metrics_recorded ON performance_metrics(recorded_at DESC);

-- Insert default admin user (password: admin123)
INSERT INTO users (email, hashed_password, full_name, is_admin) VALUES 
('admin@company.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3QJflHQrxG', 'System Administrator', TRUE);
