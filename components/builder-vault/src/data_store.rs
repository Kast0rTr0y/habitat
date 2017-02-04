// Copyright (c) 2016-2017 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The PostgreSQL backend for the Vault.

use db::pool::Pool;
use db::migration::Migrator;
use protocol::{vault, jobsrv, InstaId};
use postgres;
use protobuf::RepeatedField;

use config::Config;
use error::{Result, Error};

#[derive(Debug, Clone)]
pub struct DataStore {
    pub pool: Pool,
}

impl DataStore {
    pub fn new(config: &Config) -> Result<DataStore> {
        let pool = Pool::new(&config.datastore_connection_url,
                             config.pool_size,
                             config.datastore_connection_retry_ms,
                             config.datastore_connection_timeout,
                             config.datastore_connection_test)?;
        Ok(DataStore { pool: pool })
    }

    pub fn from_pool(pool: Pool) -> Result<DataStore> {
        Ok(DataStore { pool: pool })
    }

    pub fn setup(&self) -> Result<()> {
        let mut migrator = Migrator::new(&self.pool);
        migrator.setup()?;
        migrator.migrate("vault", r#"CREATE SEQUENCE IF NOT EXISTS origin_id_seq;"#)?;
        migrator.migrate("vault",
             r#"CREATE OR REPLACE FUNCTION next_id_v1(sequence_id regclass, OUT result bigint) AS $$
                DECLARE
                    our_epoch bigint := 1409266191000;
                    seq_id bigint;
                    now_millis bigint;
                    shard_id int := 0;
                BEGIN
                    SELECT nextval(sequence_id) % 1024 INTO seq_id;
                    SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000) INTO now_millis;
                    result := (now_millis - our_epoch) << 23;
                    result := result | (seq_id << 13);
                    result := result | (shard_id);
                END;
                $$ LANGUAGE PLPGSQL;"#)?;
        migrator.migrate("vault",
                     r#"CREATE TABLE origins (
                    id bigint PRIMARY KEY DEFAULT next_id_v1('origin_id_seq'),
                    name text UNIQUE,
                    owner_id bigint,
                    created_at timestamptz DEFAULT now(),
                    updated_at timestamptz
             )"#)?;
        migrator.migrate("vault",
                     r#"CREATE TABLE origin_members (
                    origin_id bigint REFERENCES origins(id),
                    origin_name text,
                    account_id bigint,
                    account_name text,
                    created_at timestamptz DEFAULT now(),
                    updated_at timestamptz,
                    PRIMARY KEY (origin_id, account_id)
                )"#)?;
        migrator.migrate("vault",
                     r#"CREATE OR REPLACE FUNCTION insert_origin_member_v1 (
                     om_origin_id bigint,
                     om_origin_name text,
                     om_account_id bigint,
                     om_account_name text
                 ) RETURNS void AS $$
                     BEGIN
                         INSERT INTO origin_members (origin_id, origin_name, account_id, account_name)
                                VALUES (om_origin_id, om_origin_name, om_account_id, om_account_name);
                     END 
                 $$ LANGUAGE plpgsql VOLATILE"#)?;
        migrator.migrate("vault",
                     r#"CREATE OR REPLACE FUNCTION insert_origin_v1 (
                     origin_name text,
                     origin_owner_id bigint,
                     origin_owner_name text
                 ) RETURNS void AS $$
                     DECLARE
                       origin_id bigint;
                     BEGIN
                         INSERT INTO origins (name, owner_id) 
                                VALUES (origin_name, origin_owner_id) RETURNING id into origin_id;
                         PERFORM insert_origin_member_v1(origin_id, origin_name, origin_owner_id, origin_owner_name);
                     END 
                 $$ LANGUAGE plpgsql VOLATILE"#)?;
        migrator.migrate("vault",
                     r#"CREATE SEQUENCE IF NOT EXISTS origin_secret_key_id_seq;"#)?;
        migrator.migrate("vault",
                     r#"CREATE TABLE origin_secret_keys (
                    id bigint PRIMARY KEY DEFAULT next_id_v1('origin_secret_key_id_seq'),
                    origin_id bigint REFERENCES origins(id),
                    owner_id bigint,
                    name text,
                    revision text,
                    full_name text,
                    body bytea,
                    created_at timestamptz DEFAULT now(),
                    updated_at timestamptz
             )"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE VIEW origins_with_secret_key_full_name_v1 AS
                        SELECT origins.id, origins.name, origins.owner_id,
                               origin_secret_keys.full_name AS private_key_name
                          FROM origins
                          LEFT OUTER JOIN origin_secret_keys ON (origins.id = origin_secret_keys.origin_id)
                          ORDER BY origins.id, origin_secret_keys.full_name DESC"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE FUNCTION insert_origin_secret_key_v1 (
                    osk_origin_id bigint,
                    osk_owner_id bigint,
                    osk_name text,
                    osk_revision text,
                    osk_full_name text,
                    osk_body bytea
                 ) RETURNS void AS $$
                     BEGIN
                         INSERT INTO origin_secret_keys (origin_id, owner_id, name, revision, full_name, body) 
                                VALUES (osk_origin_id, osk_owner_id, osk_name, osk_revision, osk_full_name, osk_body);
                     END 
                 $$ LANGUAGE plpgsql VOLATILE"#)?;
        migrator.migrate("vault",
                     r#"CREATE OR REPLACE FUNCTION get_origin_secret_key_v1 (
                    osk_name text
                 ) RETURNS SETOF origin_secret_keys AS $$
                    BEGIN
                        RETURN QUERY SELECT * FROM origin_secret_keys WHERE name = osk_name 
                          ORDER BY full_name DESC
                          LIMIT 1;
                        RETURN;
                    END
                    $$ LANGUAGE plpgsql STABLE"#)?;
        migrator.migrate("vault",
                     r#"CREATE SEQUENCE IF NOT EXISTS origin_invitations_id_seq;"#)?;
        migrator.migrate("vault",
                     r#"CREATE TABLE origin_invitations (
                        id bigint PRIMARY KEY DEFAULT next_id_v1('origin_invitations_id_seq'),
                        origin_id bigint REFERENCES origins(id),
                        origin_name text,
                        account_id bigint,
                        account_name text,
                        owner_id bigint,
                        ignored bool DEFAULT false,
                        created_at timestamptz DEFAULT now(),
                        updated_at timestamptz,
                        UNIQUE (origin_id, account_id)
                        )"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE FUNCTION insert_origin_invitation_v1 (
                    oi_origin_id bigint,
                    oi_origin_name text,
                    oi_account_id bigint,
                    oi_account_name text,
                    oi_owner_id bigint
                 ) RETURNS void AS $$
                     BEGIN
                        IF NOT EXISTS (SELECT true FROM origin_members WHERE origin_id = oi_origin_id AND account_id = oi_account_id) THEN
                             INSERT INTO origin_invitations (origin_id, origin_name, account_id, account_name, owner_id)
                                    VALUES (oi_origin_id, oi_origin_name, oi_account_id, oi_account_name, oi_owner_id)
                                    ON CONFLICT DO NOTHING;
                        END IF;
                     END 
                 $$ LANGUAGE plpgsql VOLATILE"#)?;
        migrator.migrate("vault",
                     r#"CREATE OR REPLACE FUNCTION get_origin_invitations_for_origin_v1 (
                   oi_origin_id bigint
                 ) RETURNS SETOF origin_invitations AS $$
                    BEGIN
                        RETURN QUERY SELECT * FROM origin_invitations WHERE origin_id = oi_origin_id
                          ORDER BY account_name ASC;
                        RETURN;
                    END
                    $$ LANGUAGE plpgsql STABLE"#)?;
        migrator.migrate("vault",
                     r#"CREATE OR REPLACE FUNCTION get_origin_invitations_for_account_v1 (
                   oi_account_id bigint
                 ) RETURNS SETOF origin_invitations AS $$
                    BEGIN
                        RETURN QUERY SELECT * FROM origin_invitations WHERE account_id = oi_account_id AND ignored = false
                          ORDER BY origin_name ASC;
                        RETURN;
                    END
                    $$ LANGUAGE plpgsql STABLE"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE FUNCTION accept_origin_invitation_v1 (
                   oi_invite_id bigint, oi_ignore bool
                 ) RETURNS void AS $$
                    DECLARE
                        oi_origin_id bigint;
                        oi_origin_name text;
                        oi_account_id bigint;
                        oi_account_name text;
                    BEGIN
                        IF oi_ignore = true THEN
                            UPDATE origin_invitations SET ignored = true, updated_at = now() WHERE id = oi_invite_id;
                        ELSE
                            SELECT origin_id, origin_name, account_id, account_name INTO oi_origin_id, oi_origin_name, oi_account_id, oi_account_name FROM origin_invitations WHERE id = oi_invite_id;
                            PERFORM insert_origin_member_v1(oi_origin_id, oi_origin_name, oi_account_id, oi_account_name);
                            DELETE FROM origin_invitations WHERE id = oi_invite_id;
                        END IF;
                    END
                    $$ LANGUAGE plpgsql VOLATILE"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE FUNCTION list_origin_members_v1 (
                   om_origin_id bigint
                 ) RETURNS TABLE(account_name text) AS $$
                    BEGIN
                        RETURN QUERY SELECT origin_members.account_name FROM origin_members WHERE origin_id = om_origin_id
                          ORDER BY account_name ASC;
                        RETURN;
                    END
                    $$ LANGUAGE plpgsql STABLE"#)?;
        migrator.migrate("vault",
                 r#"CREATE OR REPLACE FUNCTION check_account_in_origin_members_v1 (
                   om_origin_name text,
                   om_account_id bigint
                 ) RETURNS TABLE(is_member bool) AS $$
                    BEGIN
                        RETURN QUERY SELECT true FROM origin_members WHERE origin_name = om_origin_name AND account_id = om_account_id;
                        RETURN;
                    END
                    $$ LANGUAGE plpgsql STABLE"#)?;

        Ok(())
    }

    pub fn check_account_in_origin(&self, coar: &vault::CheckOriginAccessRequest) -> Result<bool> {
        let conn = self.pool.get()?;
        let rows = &conn.query("SELECT * FROM check_account_in_origin_members_v1($1, $2)",
                   &[&coar.get_origin_name(), &(coar.get_account_id() as i64)])
            .map_err(Error::OriginMemberList)?;
        if rows.len() != 0 { Ok(true) } else { Ok(false) }
    }

    pub fn list_origin_members(&self,
                               omlr: &vault::OriginMemberListRequest)
                               -> Result<Option<Vec<String>>> {
        let conn = self.pool.get()?;
        let rows = &conn.query("SELECT * FROM list_origin_members_v1($1)",
                   &[&(omlr.get_origin_id() as i64)])
            .map_err(Error::OriginMemberList)?;
        if rows.len() != 0 {
            let mut list_of_members = Vec::new();
            for row in rows {
                list_of_members.push(row.get("account_name"));
            }
            Ok(Some(list_of_members))
        } else {
            Ok(None)
        }
    }

    pub fn accept_origin_invitation(&self,
                                    oiar: &vault::OriginInvitationAcceptRequest)
                                    -> Result<()> {
        let conn = self.pool.get()?;
        let tr = conn.transaction().map_err(Error::DbTransactionStart)?;
        tr.execute("SELECT * FROM accept_origin_invitation_v1($1, $2)",
                     &[&(oiar.get_invite_id() as i64), &oiar.get_ignore()])
            .map_err(Error::OriginInvitationAccept)?;
        tr.commit().map_err(Error::DbTransactionCommit)?;
        Ok(())
    }

    pub fn list_origin_invitations_for_account(&self,
                                               oilr: &vault::AccountInvitationListRequest)
                                               -> Result<Option<Vec<vault::OriginInvitation>>> {
        let conn = self.pool.get()?;
        let rows = &conn.query("SELECT * FROM get_origin_invitations_for_account_v1($1)",
                   &[&(oilr.get_account_id() as i64)])
            .map_err(Error::OriginInvitationListForAccount)?;
        if rows.len() != 0 {
            let mut list_of_oi: Vec<vault::OriginInvitation> = Vec::new();
            for row in rows {
                list_of_oi.push(self.row_to_origin_invitation(&row));
            }
            Ok(Some(list_of_oi))
        } else {
            Ok(None)
        }
    }

    pub fn list_origin_invitations_for_origin(&self,
                                              oilr: &vault::OriginInvitationListRequest)
                                              -> Result<Option<Vec<vault::OriginInvitation>>> {
        let conn = self.pool.get()?;
        let rows = &conn.query("SELECT * FROM get_origin_invitations_for_origin_v1($1)",
                   &[&(oilr.get_origin_id() as i64)])
            .map_err(Error::OriginInvitationListForOrigin)?;
        if rows.len() != 0 {
            let mut list_of_oi: Vec<vault::OriginInvitation> = Vec::new();
            for row in rows {
                list_of_oi.push(self.row_to_origin_invitation(&row));
            }
            Ok(Some(list_of_oi))
        } else {
            Ok(None)
        }
    }

    fn row_to_origin_invitation(&self, row: &postgres::rows::Row) -> vault::OriginInvitation {
        let mut oi = vault::OriginInvitation::new();
        let oi_id: i64 = row.get("id");
        oi.set_id(oi_id as u64);
        let oi_account_id: i64 = row.get("account_id");
        oi.set_account_id(oi_account_id as u64);
        oi.set_account_name(row.get("account_name"));
        let oi_origin_id: i64 = row.get("origin_id");
        oi.set_origin_id(oi_origin_id as u64);
        oi.set_origin_name(row.get("origin_name"));
        let oi_owner_id: i64 = row.get("owner_id");
        oi.set_owner_id(oi_owner_id as u64);
        oi
    }

    pub fn create_origin_invitation(&self, oic: &vault::OriginInvitationCreate) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute("SELECT insert_origin_invitation_v1($1, $2, $3, $4, $5)",
                     &[&(oic.get_origin_id() as i64),
                       &oic.get_origin_name(),
                       &(oic.get_account_id() as i64),
                       &oic.get_account_name(),
                       &(oic.get_owner_id() as i64)])
            .map_err(Error::OriginInvitationCreate)?;
        Ok(())
    }

    pub fn create_origin_secret_key(&self, osk: &vault::OriginSecretKeyCreate) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute("SELECT insert_origin_secret_key_v1($1, $2, $3, $4, $5, $6)",
                     &[&(osk.get_origin_id() as i64),
                       &(osk.get_owner_id() as i64),
                       &osk.get_name(),
                       &osk.get_revision(),
                       &format!("{}-{}", osk.get_name(), osk.get_revision()),
                       &osk.get_body()])
            .map_err(Error::OriginSecretKeyCreate)?;
        Ok(())
    }

    pub fn get_origin_secret_key(&self,
                                 osk_get: &vault::OriginSecretKeyGet)
                                 -> Result<Option<vault::OriginSecretKey>> {
        let conn = self.pool.get()?;
        let rows = &conn.query("SELECT * FROM get_origin_secret_key_v1($1)",
                   &[&osk_get.get_origin()])
            .map_err(Error::OriginSecretKeyGet)?;
        if rows.len() != 0 {
            // We just checked - we know there is a value here
            let row = rows.iter().nth(0).unwrap();
            let mut osk = vault::OriginSecretKey::new();
            let osk_id: i64 = row.get("id");
            osk.set_id(osk_id as u64);
            let osk_origin_id: i64 = row.get("origin_id");
            osk.set_origin_id(osk_origin_id as u64);
            osk.set_name(row.get("name"));
            osk.set_revision(row.get("revision"));
            osk.set_body(row.get("body"));
            let osk_owner_id: i64 = row.get("owner_id");
            osk.set_owner_id(osk_owner_id as u64);
            Ok(Some(osk))
        } else {
            Ok(None)
        }
    }

    pub fn create_origin(&self, origin: &vault::OriginCreate) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute("SELECT insert_origin_v1($1, $2, $3)",
                     &[&origin.get_name(),
                       &(origin.get_owner_id() as i64),
                       &origin.get_owner_name()])
            .map_err(Error::OriginCreate)?;
        Ok(())
    }

    pub fn get_origin(&self, origin_get: &vault::OriginGet) -> Result<Option<vault::Origin>> {
        self.get_origin_by_name(origin_get.get_name())
    }

    pub fn get_origin_by_name(&self, origin_name: &str) -> Result<Option<vault::Origin>> {
        let conn = self.pool.get()?;
        let rows =
            &conn.query("SELECT * FROM origins_with_secret_key_full_name_v1 WHERE name = $1 LIMIT \
                        1",
                       &[&origin_name])
                .map_err(Error::OriginGet)?;
        if rows.len() != 0 {
            let row = rows.iter().nth(0).unwrap();
            let mut origin = vault::Origin::new();
            let oid: i64 = row.get("id");
            origin.set_id(oid as u64);
            origin.set_name(row.get("name"));
            let ooid: i64 = row.get("owner_id");
            origin.set_owner_id(ooid as u64);
            let private_key_name: Option<String> = row.get("private_key_name");
            if let Some(pk) = private_key_name {
                origin.set_private_key_name(pk);
            }
            Ok(Some(origin))
        } else {
            Ok(None)
        }
    }
}
