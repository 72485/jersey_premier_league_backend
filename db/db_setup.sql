-- 1. DROP the table if it exists (for clean restarts and schema change)
--DROP TABLE IF EXISTS users;

-- 2. CREATE the users table with SERIAL for auto-incrementing ID
CREATE TABLE IF NOT EXISTS users (
    -- Unique identifier for the user.
    -- The SERIAL type creates an integer column that automatically
    -- increments and is implicitly NOT NULL. It's the standard for auto-ID.
    id SERIAL PRIMARY KEY,

    -- User details
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL, -- Email must be unique for login

    -- Password storage
    password_hash TEXT NOT NULL,

    -- Application-specific field for the Fantasy Premier League Team ID
    fpl_team_ID VARCHAR(50), -- Nullable

    -- Auditing fields
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- 3. Add an index for faster lookups based on email (used during login)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Optional: Display the newly created table (for verification)

-- History/Audit Log Table for the users table
CREATE TABLE IF NOT EXISTS users_history (
    history_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    action_type VARCHAR(10) NOT NULL, -- INSERT, UPDATE
    old_data JSONB, -- Stores previous row data for UPDATE/DELETE
    new_data JSONB NOT NULL, -- Stores current row data
    changed_by TEXT DEFAULT 'Application', -- Could store user ID from JWT if passed, but easier as a simple flag
    change_timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- Function to log changes to the users table
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
DECLARE
    -- Variable to hold the old and new row data as JSONB
    v_old_data JSONB;
    v_new_data JSONB;
BEGIN
    -- Determine the action type
    IF TG_OP = 'INSERT' THEN
        v_new_data := to_jsonb(NEW);
        INSERT INTO users_history (user_id, action_type, new_data)
        VALUES (NEW.id, 'INSERT', v_new_data);
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        -- Convert OLD and NEW records to JSONB, excluding the sensitive password_hash
        v_old_data := row_to_json(OLD)::jsonb - 'password_hash' - 'created_at';
        v_new_data := row_to_json(NEW)::jsonb - 'password_hash' - 'created_at';

        -- Check if anything OTHER THAN the password hash changed
        IF v_old_data IS DISTINCT FROM v_new_data THEN
            -- If the password hash is the only change, we still log it,
            -- but the v_old_data and v_new_data will look the same since we exclude the hash.
            -- We'll log the full row data (excluding the hash) for comparison.

            INSERT INTO users_history (user_id, action_type, old_data, new_data)
            VALUES (NEW.id, 'UPDATE', v_old_data, v_new_data);
        END IF;

        RETURN NEW;

    -- Note: We are not implementing DELETE historization yet, but it would follow the UPDATE logic
    -- ELSIF TG_OP = 'DELETE' THEN
    --    v_old_data := to_jsonb(OLD);
    --    INSERT INTO users_history (user_id, action_type, old_data)
    --    VALUES (OLD.id, 'DELETE', v_old_data);
    --    RETURN OLD;

    END IF;
    RETURN NULL; -- result is ignored for BEFORE triggers
END;
$$ LANGUAGE plpgsql;

-- Create the trigger that fires BEFORE any INSERT or UPDATE on the users table
DROP TRIGGER IF EXISTS users_audit_trigger ON users;

CREATE TRIGGER users_audit_trigger
BEFORE INSERT OR UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION log_user_changes();

