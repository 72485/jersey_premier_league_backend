-- 1. DROP the table if it exists (for clean restarts and schema change)
-- This line is usually commented out unless you want a fresh start
-- DROP TABLE IF EXISTS users;

-- 2. CREATE the users table with SERIAL for auto-incrementing ID
CREATE TABLE IF NOT EXISTS users (
    -- Unique identifier for the user.
    id SERIAL PRIMARY KEY,

    -- User details
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL, -- Email must be unique for login

    -- Password storage
    password_hash TEXT NOT NULL,

    -- Application-specific field for the Fantasy Premier League Team ID
    fpl_team_id VARCHAR(50), -- Nullable

    -- ⚡ FIX: NEW COLUMN for Email Verification
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,

    -- ⚡ FIX: NEW COLUMN for the Verification Token
    verification_token VARCHAR(500), -- Token for verification link

    -- Auditing fields
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- 3. Add an index for faster lookups based on email (used during login)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- History/Audit Log Table for the users table
CREATE TABLE IF NOT EXISTS users_history (
    history_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    action_type VARCHAR(10) NOT NULL, -- INSERT, UPDATE
    old_data JSONB, -- Stores previous row data for UPDATE/DELETE
    new_data JSONB NOT NULL, -- Stores current row data
    changed_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- 4. Create a trigger function to log user changes
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Exclude sensitive/audit fields from the history log
        v_new_data := row_to_json(NEW)::jsonb - 'password_hash' - 'created_at' - 'verification_token';

        INSERT INTO users_history (user_id, action_type, new_data)
        VALUES (NEW.id, 'INSERT', v_new_data);

        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        -- Convert OLD and NEW records to JSONB, excluding the sensitive password_hash and verification_token
        v_old_data := row_to_json(OLD)::jsonb - 'password_hash' - 'created_at' - 'verification_token';
        v_new_data := row_to_json(NEW)::jsonb - 'password_hash' - 'created_at' - 'verification_token';

        -- Check if anything OTHER THAN the excluded columns changed
        IF v_old_data IS DISTINCT FROM v_new_data THEN
            INSERT INTO users_history (user_id, action_type, old_data, new_data)
            VALUES (NEW.id, 'UPDATE', v_old_data, v_new_data);
        END IF;

        RETURN NEW;

    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- 5. Attach the trigger to the users table
CREATE OR REPLACE TRIGGER users_audit_trigger
BEFORE INSERT OR UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION log_user_changes();