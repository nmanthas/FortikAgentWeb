-- QuickStart Milestones 2-4: the QuickStart card's activity counts and recent
-- decisions read only QuickStart MCP actions of the last day.
CREATE INDEX actions_quickstart_ts ON actions (ts DESC)
    WHERE system = 'netsuite' AND target ->> 'integration' = 'netsuite_quickstart';
