-- =================================================================
-- F1_LEAGUE: Defines the instance of the JPL Grand Prix competition
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_LEAGUE (
    league_id SERIAL PRIMARY KEY,
    fpl_league_id VARCHAR(50) UNIQUE NOT NULL, -- The official FPL mini-league ID
    name VARCHAR(255) NOT NULL,
    current_gameweek INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    setup_timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- =================================================================
-- F1_CONSTRUCTORS: Defines the 10 two-person teams (e.g., Red Bull)
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_CONSTRUCTORS (
    constructor_id SERIAL PRIMARY KEY,
    league_id INT NOT NULL REFERENCES F1_LEAGUE(league_id),
    f1_team_name VARCHAR(100) UNIQUE NOT NULL, -- e.g., 'Red Bull', 'Ferrari'
    logo_url TEXT, -- Optional: for displaying team logo in app
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
);

-- =================================================================
-- F1_DRIVER_ASSIGNMENTS: Maps two users (from the global 'users' table)
-- to one Constructor team and defines their role (A or B).
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_DRIVER_ASSIGNMENTS (
    assignment_id SERIAL PRIMARY KEY,
    league_id INT NOT NULL REFERENCES F1_LEAGUE(league_id),
    user_id INT NOT NULL REFERENCES users(id), -- Links to the global users table
    constructor_id INT NOT NULL REFERENCES F1_CONSTRUCTORS(constructor_id),
    driver_role VARCHAR(10) NOT NULL CHECK (driver_role IN ('Driver A', 'Driver B')), -- For Constructor's Championship tracking

    -- Constraint to ensure a user is only assigned once per league
    UNIQUE (league_id, user_id),
    -- Constraint to ensure only two drivers per constructor
    UNIQUE (constructor_id, driver_role)
);

-- =================================================================
-- F1_CHIP_USAGE: Tracks the season-long usage of F1-specific chips
-- (Safety Car and DRS Boost) for the Declaration Requirement.
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_CHIP_USAGE (
    usage_id SERIAL PRIMARY KEY,
    league_id INT NOT NULL REFERENCES F1_LEAGUE(league_id),
    user_id INT NOT NULL REFERENCES users(id),
    gameweek INT NOT NULL,
    chip_type VARCHAR(20) NOT NULL CHECK (chip_type IN ('Safety Car', 'DRS Boost')),

    -- Ensure each chip is only used once per manager per league
    UNIQUE (league_id, user_id, chip_type)
);

-- =================================================================
-- F1_GW_STATS: The central transaction table. Stores all FPL, Bonus,
-- and F1 point calculations for every manager, every Gameweek.
-- This table is critical for calculating ranks and cumulative scores.
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_GW_STATS (
    gw_stat_id SERIAL PRIMARY KEY,
    league_id INT NOT NULL REFERENCES F1_LEAGUE(league_id),
    user_id INT NOT NULL REFERENCES users(id),
    gameweek INT NOT NULL,

    -- FPL Scores
    raw_fpl_score INT NOT NULL,
    transfer_hits INT NOT NULL,

    -- FPL Chip Used (needed for DOTD ineligibility check)
    fpl_chip_used VARCHAR(30), -- Stores 'Wildcard', 'Triple Captain', etc. (NULL if none)

    -- F1 Points Calculation Inputs
    is_race_gw BOOLEAN NOT NULL, -- True for even GWs

    -- Grid Position Bonus (calculated from the PREVIOUS Qualifying GW rank)
    qual_gw_rank INT, -- NULL for GW 1, 2. Used to determine grid_fpl_bonus.
    grid_fpl_bonus INT NOT NULL DEFAULT 0, -- The FPL score advantage (+6, +4, +2)

    -- The score used for weekly ranking (FPL Score - Hits + Grid Bonus)
    net_fpl_score DECIMAL(10, 2) NOT NULL,

    -- F1 Chips Used THIS GW
    used_safety_car BOOLEAN NOT NULL DEFAULT FALSE,
    used_drs_boost BOOLEAN NOT NULL DEFAULT FALSE,

    -- F1 Points Output (Calculated based on weekly_league_rank)
    weekly_league_rank INT NOT NULL, -- Rank based on net_fpl_score (1-20)
    base_f1_points DECIMAL(10, 2) NOT NULL, -- F1 Pts before F1 chips (after top 10 tiebreaker)

    -- Bonus Points
    pole_position_f1_bonus DECIMAL(10, 2) NOT NULL DEFAULT 0, -- +3 F1 Pts if tied for 1st in Qual GW
    dotd_f1_bonus DECIMAL(10, 2) NOT NULL DEFAULT 0, -- +3 F1 Pts for DOTD (Qual or Race type)

    -- Final Result
    final_f1_points DECIMAL(10, 2) NOT NULL, -- The final score used for championship tally

    UNIQUE (league_id, user_id, gameweek) -- A manager can only have one stat row per GW per league
);


-- =================================================================
-- F1_STANDINGS: Stores cumulative points for the Championship tables.
-- This allows for fast querying without recalculating all GWs.
-- =================================================================
CREATE TABLE IF NOT EXISTS F1_STANDINGS (
    standing_id SERIAL PRIMARY KEY,
    league_id INT NOT NULL REFERENCES F1_LEAGUE(league_id),
    gameweek INT NOT NULL, -- Last GW included in the cumulative score

    -- Reference either a user or a constructor (use one or the other)
    user_id INT REFERENCES users(id), -- Null if constructor standing
    constructor_id INT REFERENCES F1_CONSTRUCTORS(constructor_id), -- Null if driver standing

    -- Core Championship Metrics
    cumulative_f1_points DECIMAL(10, 2) NOT NULL,
    cumulative_fpl_points INT NOT NULL, -- Primary tiebreaker metric
    current_rank INT NOT NULL,

    -- Tiebreaker Counts (for Drivers' Championship)
    rank_1st_place_count INT NOT NULL DEFAULT 0,
    rank_2nd_place_count INT NOT NULL DEFAULT 0,
    -- ... can extend for all 10 places if needed, or use a JSONB field for simplicity

    -- Constraint to enforce only one type of standing per entry
    CHECK ((user_id IS NOT NULL AND constructor_id IS NULL) OR (user_id IS NULL AND constructor_id IS NOT NULL)),

    -- Constraint to ensure a single cumulative entry per GW for each driver/constructor
    UNIQUE (league_id, gameweek, user_id),
    UNIQUE (league_id, gameweek, constructor_id)
);
