-- Node overlay and Device alias pools stay inside the client overlay frame.
--
-- Clients refuse a map whose addresses leave their fixed overlay frame
-- (100.64.0.0/10, 198.18.0.0/15, fd00::/8), so a map that carries one address
-- from a pool outside it is refused whole. Network creation already keeps
-- overlay prefixes inside 100.64.0.0/10 and Workspace IPv6 /48s inside
-- fd00::/8, but the operator tool accepted Device alias pools anywhere. The
-- tool now requires 198.18.0.0/15 or fd00::/8; this constraint holds the
-- frame for every writer. Workspace service pools are not carried in maps
-- and keep their own rules.
--
-- Adding the constraint checks the existing rows: a deployment with a pool
-- outside the frame stops here, before any client refuses its maps.
ALTER TABLE mesh.address_pool
    ADD CONSTRAINT address_pool_frame_check CHECK (
        purpose = 'workspace_service'
        OR prefix <<= '100.64.0.0/10'::CIDR
        OR prefix <<= '198.18.0.0/15'::CIDR
        OR prefix <<= 'fd00::/8'::CIDR
    );
