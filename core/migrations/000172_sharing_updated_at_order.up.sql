-- Schema 172: keep updated_at in order on the Resource sharing rows whatever
-- clock stamped the previous version.
--
-- The database clock is the single source of truth for every persisted
-- timestamp. Before this release, MeshCore stamped the share mutations
-- (create, decide, activate, revoke) with its own host clock, while the
-- Private Endpoint publication, withdrawal and expiry workers stamp the same
-- rows with the database clock. The transition triggers reject an update
-- whose updated_at is older than the previous version's (23514): with
-- MeshCore 200 ms ahead of the database, finalizing the withdrawal of a just
-- activated Private Endpoint failed; with MeshCore behind, a revocation after
-- a publication failed. The new binary stamps share mutations with the
-- database transaction time, but a share row may still carry a host-clock
-- time from a previous binary, and two database transactions that overlap
-- may stamp out of commit order (a transaction's own time is when it began).
--
-- keep_updated_at_order_v1 raises a new version's updated_at to the previous
-- version's when it is older, so updated_at never goes backwards and an
-- ordering-only difference never fails a write. It runs before every other
-- BEFORE UPDATE trigger of these tables (triggers fire in name order), so the
-- transition checks see the kept order and still enforce every other rule.
-- It changes no other column: created_at, ended_at, withdrawn_at, ready_at
-- and activated_at keep the time their writer gave them, and their CHECK
-- constraints stay as they are.

CREATE FUNCTION mesh_ops.keep_updated_at_order_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.updated_at < OLD.updated_at THEN
        NEW.updated_at := OLD.updated_at;
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.keep_updated_at_order_v1() FROM PUBLIC;

CREATE TRIGGER resource_export_clock_order BEFORE UPDATE ON mesh.resource_export
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER share_offer_clock_order BEFORE UPDATE ON mesh.share_offer
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER trust_contract_clock_order BEFORE UPDATE ON mesh.trust_contract
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER imported_resource_clock_order BEFORE UPDATE ON mesh.imported_resource
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER imported_resource_access_name_clock_order BEFORE UPDATE ON mesh.imported_resource_access_name
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER imported_resource_dns_publication_clock_order BEFORE UPDATE ON mesh.imported_resource_dns_publication
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER private_endpoint_clock_order BEFORE UPDATE ON mesh.private_endpoint
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
CREATE TRIGGER federation_alias_lease_clock_order BEFORE UPDATE ON mesh.federation_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v1();
