-- Schema 173: log when the Resource sharing rows keep updated_at in order.
--
-- keep_updated_at_order_v2 is v1 (schema 172) that also writes one LOG line
-- to the server log whenever it raises a new version's updated_at to the
-- previous version's: the table, the version and by how much. Since share
-- writers stamp the database clock, a raise means a row a previous binary
-- stamped with a host clock ahead of the database, or two transactions that
-- overlapped; a steady stream of them is worth a look. LOG goes to the
-- server log only, never to the client, and costs nothing when no raise
-- happens. The triggers of schema 172 now call v2; v1 stays.

CREATE FUNCTION mesh_ops.keep_updated_at_order_v2()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE LOG 'kept updated_at in order on %: version % was % behind version %',
            TG_TABLE_NAME, NEW.version, OLD.updated_at - NEW.updated_at, OLD.version;
        NEW.updated_at := OLD.updated_at;
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.keep_updated_at_order_v2() FROM PUBLIC;

DROP TRIGGER resource_export_clock_order ON mesh.resource_export;
CREATE TRIGGER resource_export_clock_order BEFORE UPDATE ON mesh.resource_export
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER share_offer_clock_order ON mesh.share_offer;
CREATE TRIGGER share_offer_clock_order BEFORE UPDATE ON mesh.share_offer
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER trust_contract_clock_order ON mesh.trust_contract;
CREATE TRIGGER trust_contract_clock_order BEFORE UPDATE ON mesh.trust_contract
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER imported_resource_clock_order ON mesh.imported_resource;
CREATE TRIGGER imported_resource_clock_order BEFORE UPDATE ON mesh.imported_resource
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER imported_resource_access_name_clock_order ON mesh.imported_resource_access_name;
CREATE TRIGGER imported_resource_access_name_clock_order BEFORE UPDATE ON mesh.imported_resource_access_name
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER imported_resource_dns_publication_clock_order ON mesh.imported_resource_dns_publication;
CREATE TRIGGER imported_resource_dns_publication_clock_order BEFORE UPDATE ON mesh.imported_resource_dns_publication
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER private_endpoint_clock_order ON mesh.private_endpoint;
CREATE TRIGGER private_endpoint_clock_order BEFORE UPDATE ON mesh.private_endpoint
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
DROP TRIGGER federation_alias_lease_clock_order ON mesh.federation_alias_lease;
CREATE TRIGGER federation_alias_lease_clock_order BEFORE UPDATE ON mesh.federation_alias_lease
    FOR EACH ROW EXECUTE FUNCTION mesh_ops.keep_updated_at_order_v2();
