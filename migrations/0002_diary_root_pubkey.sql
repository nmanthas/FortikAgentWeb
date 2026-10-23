-- Store the public key next to each sealed daily root so a root sealed
-- before a key rotation still verifies afterwards.
ALTER TABLE diary_roots ADD COLUMN public_key text NOT NULL DEFAULT '';
