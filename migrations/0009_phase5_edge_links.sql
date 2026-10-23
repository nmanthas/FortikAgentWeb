-- Phase 5 review: exact attribution of egress through a shared app.
-- An agent's send through an app (agent -> app:gmail) and the app's egress to
-- an external domain (app:gmail -> domain:X) are two edges; their capped
-- sample action ids cannot link them in a busy window. One row per
-- (window, origin agent, hub app, destination, verb) records that this agent's
-- calls through this hub went to this destination, so path traces and the
-- external/agent views never attribute a leak to an agent that did not send
-- to that destination. Pruned with the edges (map.retention).
CREATE TABLE edge_links (
    window_start  timestamptz NOT NULL,
    origin        text NOT NULL,                     -- agent:<id>
    hub           text NOT NULL,                     -- app:<system> (the edge's from_node toward the domain)
    dest          text NOT NULL,                     -- domain:<host>
    verb          text NOT NULL,
    count         bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (window_start, hub, dest, verb, origin)
);
CREATE INDEX edge_links_origin ON edge_links (origin, window_start DESC);
