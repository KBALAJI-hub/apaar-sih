# APAAR Verify --- Supabase Database Schema

**Project:** SIH Problem Statement 26263\
**Purpose:** Shareable snapshot of the current `public` schema exported
from Supabase SQL Editor.\
**Source:** Supabase schema-inspection query supplied by the project
team.

> **Notes** - This document describes the schema captured in the export;
> it is not a migration script. - `estimated_rows` comes from PostgreSQL
> statistics and is approximate, not an exact count. - `YES` under
> Identity means PostgreSQL generates values using an identity column. -
> Nullable means the database permits `NULL`; `NO` means the column is
> `NOT NULL`.

## Table overview

  Table                      Estimated rows   Columns   Constraints   Indexes
  ------------------------ ---------------- --------- ------------- ---------
  `anomalyalert`                          0         6             2         3
  `apaarregistry`                        20         6             3         2
  `auditlog`                              0        10             2         1
  `auditlog_legacy`                       0        14             3         5
  `institution`                       13089        15             3         7
  `institution_api_keys`                  0         8             3         3
  `program`                           58298        15             4         6
  `setting`                               0         3             2         2
  `student`                              10        24             7         4
  `user`                                  3         8             3         4
  `validationflag`                        0        15             7         6
  `verificationlog`                       0        12             5         6

## Detailed schema

### `anomalyalert`

-   **Estimated rows:** 0

#### Columns

  ------------------------------------------------------------------------------------------------
  Column             Data type                    Nullable    Default     Identity    Identity
                                                                                      generation
  ------------------ ---------------------------- ----------- ----------- ----------- ------------
  `id`               `bigint`                     NO          ---         YES         BY DEFAULT

  `institution_id`   `bigint`                     NO          ---         NO          ---

  `code`             `text`                       NO          ---         NO          ---

  `score`            `double precision`           NO          ---         NO          ---

  `reason`           `text`                       NO          ---         NO          ---

  `created_at`       `timestamp with time zone`   NO          `now()`     NO          ---
  ------------------------------------------------------------------------------------------------

#### Constraints

  ------------------------------------------------------------------------------------------------------------------------
  Name                                 Type                    Definition
  ------------------------------------ ----------------------- -----------------------------------------------------------
  `anomalyalert_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id)`

  `anomalyalert_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`
  ------------------------------------------------------------------------------------------------------------------------

#### Indexes

  ---------------------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ---------------------------------------------------------------------------------------------------
  `anomalyalert_pkey`                 `CREATE UNIQUE INDEX anomalyalert_pkey ON public.anomalyalert USING btree (id)`

  `ix_anomalyalert_code`              `CREATE INDEX ix_anomalyalert_code ON public.anomalyalert USING btree (code)`

  `ix_anomalyalert_institution_id`    `CREATE INDEX ix_anomalyalert_institution_id ON public.anomalyalert USING btree (institution_id)`
  ---------------------------------------------------------------------------------------------------------------------------------------

### `apaarregistry`

-   **Estimated rows:** 20

#### Columns

  --------------------------------------------------------------------------------------------
  Column         Data type                    Nullable    Default     Identity    Identity
                                                                                  generation
  -------------- ---------------------------- ----------- ----------- ----------- ------------
  `apaar_id`     `text`                       NO          ---         NO          ---

  `full_name`    `text`                       NO          ---         NO          ---

  `dob`          `text`                       NO          ---         NO          ---

  `gender`       `text`                       YES         ---         NO          ---

  `created_at`   `timestamp with time zone`   NO          `now()`     NO          ---

  `id`           `bigint`                     NO          ---         YES         BY DEFAULT
  --------------------------------------------------------------------------------------------

#### Constraints

  -----------------------------------------------------------------------------------------------------------
  Name                                   Type                    Definition
  -------------------------------------- ----------------------- --------------------------------------------
  `apaarregistry_apaar_id_key`           UNIQUE                  `UNIQUE (apaar_id)`

  `apaarregistry_pkey`                   PRIMARY KEY             `PRIMARY KEY (id)`

  `mock_apaar_registry_apaar_id_check`   CHECK                   `CHECK ((apaar_id ~ '^[0-9]{12}$'::text))`
  -----------------------------------------------------------------------------------------------------------

#### Indexes

  -------------------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- -------------------------------------------------------------------------------------------------
  `apaarregistry_apaar_id_key`        `CREATE UNIQUE INDEX apaarregistry_apaar_id_key ON public.apaarregistry USING btree (apaar_id)`

  `apaarregistry_pkey`                `CREATE UNIQUE INDEX apaarregistry_pkey ON public.apaarregistry USING btree (id)`
  -------------------------------------------------------------------------------------------------------------------------------------

### `auditlog`

-   **Estimated rows:** 0

#### Columns

  -------------------------------------------------------------------------------------------
  Column        Data type                    Nullable    Default     Identity    Identity
                                                                                 generation
  ------------- ---------------------------- ----------- ----------- ----------- ------------
  `id`          `bigint`                     NO          ---         YES         BY DEFAULT

  `user_id`     `bigint`                     YES         ---         NO          ---

  `username`    `text`                       NO          ---         NO          ---

  `action`      `text`                       NO          ---         NO          ---

  `entity`      `text`                       NO          ---         NO          ---

  `entity_id`   `text`                       YES         ---         NO          ---

  `details`     `text`                       YES         ---         NO          ---

  `timestamp`   `timestamp with time zone`   NO          `now()`     NO          ---

  `prev_hash`   `text`                       NO          ---         NO          ---

  `row_hash`    `text`                       NO          ---         NO          ---
  -------------------------------------------------------------------------------------------

#### Constraints

  --------------------------------------------------------------------------------------------------------------------
  Name                      Type                    Definition
  ------------------------- ----------------------- ------------------------------------------------------------------
  `auditlog_pkey`           PRIMARY KEY             `PRIMARY KEY (id)`

  `auditlog_user_id_fkey`   FOREIGN KEY             `FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE SET NULL`
  --------------------------------------------------------------------------------------------------------------------

#### Indexes

  -------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- -------------------------------------------------------------------------
  `auditlog_pkey`                     `CREATE UNIQUE INDEX auditlog_pkey ON public.auditlog USING btree (id)`

  -------------------------------------------------------------------------------------------------------------

### `auditlog_legacy`

-   **Estimated rows:** 0

#### Columns

  ----------------------------------------------------------------------------------------------------
  Column             Data type                    Nullable    Default         Identity    Identity
                                                                                          generation
  ------------------ ---------------------------- ----------- --------------- ----------- ------------
  `id`               `bigint`                     NO          ---             YES         ALWAYS

  `institution_id`   `bigint`                     YES         ---             NO          ---

  `actor_type`       `text`                       NO          ---             NO          ---

  `actor_id`         `text`                       YES         ---             NO          ---

  `action`           `text`                       NO          ---             NO          ---

  `entity_type`      `text`                       YES         ---             NO          ---

  `entity_id`        `text`                       YES         ---             NO          ---

  `details`          `jsonb`                      NO          `'{}'::jsonb`   NO          ---

  `ip_address`       `inet`                       YES         ---             NO          ---

  `created_at`       `timestamp with time zone`   NO          `now()`         NO          ---

  `user_id`          `bigint`                     YES         ---             NO          ---

  `username`         `text`                       YES         ---             NO          ---

  `entity`           `text`                       YES         ---             NO          ---

  `timestamp`        `timestamp with time zone`   YES         `now()`         NO          ---
  ----------------------------------------------------------------------------------------------------

#### Constraints

  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                               Type                    Definition
  ---------------------------------- ----------------------- -----------------------------------------------------------------------------------------------------------
  `audit_logs_actor_type_check`      CHECK                   `CHECK ((actor_type = ANY (ARRAY['INSTITUTION'::text, 'ADMIN'::text, 'SYSTEM'::text, 'STUDENT'::text])))`

  `audit_logs_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id) ON DELETE SET NULL`

  `audit_logs_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`
  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  -----------------------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- -----------------------------------------------------------------------------------------------------
  `audit_logs_pkey`                   `CREATE UNIQUE INDEX audit_logs_pkey ON public.auditlog_legacy USING btree (id)`

  `idx_audit_logs_action`             `CREATE INDEX idx_audit_logs_action ON public.auditlog_legacy USING btree (action)`

  `idx_audit_logs_created_at`         `CREATE INDEX idx_audit_logs_created_at ON public.auditlog_legacy USING btree (created_at DESC)`

  `idx_audit_logs_entity`             `CREATE INDEX idx_audit_logs_entity ON public.auditlog_legacy USING btree (entity_type, entity_id)`

  `idx_audit_logs_institution`        `CREATE INDEX idx_audit_logs_institution ON public.auditlog_legacy USING btree (institution_id)`
  -----------------------------------------------------------------------------------------------------------------------------------------

### `institution`

-   **Estimated rows:** 13089

#### Columns

  ---------------------------------------------------------------------------------------------
  Column          Data type                    Nullable    Default     Identity    Identity
                                                                                   generation
  --------------- ---------------------------- ----------- ----------- ----------- ------------
  `id`            `bigint`                     NO          ---         YES         BY DEFAULT

  `aicte_id`      `character varying`          NO          ---         NO          ---

  `name`          `text`                       NO          ---         NO          ---

  `university`    `text`                       YES         ---         NO          ---

  `state`         `character varying`          NO          ---         NO          ---

  `district`      `character varying`          YES         ---         NO          ---

  `address`       `text`                       YES         ---         NO          ---

  `type`          `character varying`          NO          ---         NO          ---

  `women`         `character varying`          YES         ---         NO          ---

  `minority`      `character varying`          YES         ---         NO          ---

  `other_id`      `character varying`          YES         ---         NO          ---

  `source_year`   `character varying`          YES         ---         NO          ---

  `created_at`    `timestamp with time zone`   NO          `now()`     NO          ---

  `updated_at`    `timestamp with time zone`   YES         `now()`     NO          ---

  `api_key`       `text`                       NO          ---         NO          ---
  ---------------------------------------------------------------------------------------------

#### Constraints

  Name                          Type          Definition
  ----------------------------- ------------- ---------------------
  `institution_api_key_key`     UNIQUE        `UNIQUE (api_key)`
  `institutions_aicte_id_key`   UNIQUE        `UNIQUE (aicte_id)`
  `institutions_pkey`           PRIMARY KEY   `PRIMARY KEY (id)`

#### Indexes

  ----------------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ----------------------------------------------------------------------------------------------
  `idx_institutions_aicte_id`         `CREATE INDEX idx_institutions_aicte_id ON public.institution USING btree (aicte_id)`

  `idx_institutions_district`         `CREATE INDEX idx_institutions_district ON public.institution USING btree (district)`

  `idx_institutions_name`             `CREATE INDEX idx_institutions_name ON public.institution USING btree (name)`

  `idx_institutions_state`            `CREATE INDEX idx_institutions_state ON public.institution USING btree (state)`

  `institution_api_key_key`           `CREATE UNIQUE INDEX institution_api_key_key ON public.institution USING btree (api_key)`

  `institutions_aicte_id_key`         `CREATE UNIQUE INDEX institutions_aicte_id_key ON public.institution USING btree (aicte_id)`

  `institutions_pkey`                 `CREATE UNIQUE INDEX institutions_pkey ON public.institution USING btree (id)`
  ----------------------------------------------------------------------------------------------------------------------------------

### `institution_api_keys`

-   **Estimated rows:** 0

#### Columns

  ------------------------------------------------------------------------------------------------
  Column             Data type                    Nullable    Default     Identity    Identity
                                                                                      generation
  ------------------ ---------------------------- ----------- ----------- ----------- ------------
  `id`               `bigint`                     NO          ---         YES         ALWAYS

  `institution_id`   `bigint`                     NO          ---         NO          ---

  `key_prefix`       `text`                       NO          ---         NO          ---

  `key_hash`         `text`                       NO          ---         NO          ---

  `is_active`        `boolean`                    NO          `true`      NO          ---

  `created_at`       `timestamp with time zone`   NO          `now()`     NO          ---

  `last_used_at`     `timestamp with time zone`   YES         ---         NO          ---

  `expires_at`       `timestamp with time zone`   YES         ---         NO          ---
  ------------------------------------------------------------------------------------------------

#### Constraints

  --------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                         Type                    Definition
  -------------------------------------------- ----------------------- -----------------------------------------------------------------------------
  `institution_api_keys_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id) ON DELETE CASCADE`

  `institution_api_keys_key_hash_key`          UNIQUE                  `UNIQUE (key_hash)`

  `institution_api_keys_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`
  --------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  ----------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                     Definition
  ---------------------------------------- -----------------------------------------------------------------------------------------------------------------
  `idx_institution_api_keys_institution`   `CREATE INDEX idx_institution_api_keys_institution ON public.institution_api_keys USING btree (institution_id)`

  `institution_api_keys_key_hash_key`      `CREATE UNIQUE INDEX institution_api_keys_key_hash_key ON public.institution_api_keys USING btree (key_hash)`

  `institution_api_keys_pkey`              `CREATE UNIQUE INDEX institution_api_keys_pkey ON public.institution_api_keys USING btree (id)`
  ----------------------------------------------------------------------------------------------------------------------------------------------------------

### `program`

-   **Estimated rows:** 58298

#### Columns

  -------------------------------------------------------------------------------------------
  Column                Data type            Nullable    Default     Identity    Identity
                                                                                 generation
  --------------------- -------------------- ----------- ----------- ----------- ------------
  `id`                  `bigint`             NO          ---         YES         ALWAYS

  `institution_id`      `bigint`             NO          ---         NO          ---

  `programme`           `text`               YES         ---         NO          ---

  `level`               `text`               NO          ---         NO          ---

  `course`              `text`               YES         ---         NO          ---

  `course_type`         `text`               YES         ---         NO          ---

  `shift`               `text`               YES         ---         NO          ---

  `availability`        `text`               YES         ---         NO          ---

  `intake`              `integer`            YES         ---         NO          ---

  `enrollment`          `integer`            YES         ---         NO          ---

  `placement`           `integer`            YES         ---         NO          ---

  `academic_year`       `text`               NO          ---         NO          ---

  `name`                `text`               NO          ---         NO          ---

  `approved_intake`     `integer`            NO          `60`        NO          ---

  `supernumerary_cap`   `double precision`   NO          `0.10`      NO          ---
  -------------------------------------------------------------------------------------------

#### Constraints

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                               Type                    Definition
  ---------------------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------
  `fk_programs_institution`          FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id) ON DELETE CASCADE`

  `programs_id_institution_unique`   UNIQUE                  `UNIQUE (id, institution_id)`

  `programs_pkey`                    PRIMARY KEY             `PRIMARY KEY (id)`

  `programs_unique_prog_idx`         UNIQUE                  `UNIQUE NULLS NOT DISTINCT (institution_id, programme, level, course, course_type, shift, availability, academic_year)`
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  `idx_programs_academic_year`        `CREATE INDEX idx_programs_academic_year ON public.program USING btree (academic_year)`

  `idx_programs_course`               `CREATE INDEX idx_programs_course ON public.program USING btree (course)`

  `idx_programs_institution`          `CREATE INDEX idx_programs_institution ON public.program USING btree (institution_id)`

  `programs_id_institution_unique`    `CREATE UNIQUE INDEX programs_id_institution_unique ON public.program USING btree (id, institution_id)`

  `programs_pkey`                     `CREATE UNIQUE INDEX programs_pkey ON public.program USING btree (id)`

  `programs_unique_prog_idx`          `CREATE UNIQUE INDEX programs_unique_prog_idx ON public.program USING btree (institution_id, programme, level, course, course_type, shift, availability, academic_year) NULLS NOT DISTINCT`
  ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### `setting`

-   **Estimated rows:** 0

#### Columns

  ------------------------------------------------------------------------
  Column      Data type   Nullable    Default     Identity    Identity
                                                              generation
  ----------- ----------- ----------- ----------- ----------- ------------
  `id`        `bigint`    NO          ---         YES         BY DEFAULT

  `key`       `text`      NO          ---         NO          ---

  `value`     `text`      NO          ---         NO          ---
  ------------------------------------------------------------------------

#### Constraints

  Name                Type          Definition
  ------------------- ------------- --------------------
  `setting_key_key`   UNIQUE        `UNIQUE (key)`
  `setting_pkey`      PRIMARY KEY   `PRIMARY KEY (id)`

#### Indexes

  ---------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ---------------------------------------------------------------------------
  `setting_key_key`                   `CREATE UNIQUE INDEX setting_key_key ON public.setting USING btree (key)`

  `setting_pkey`                      `CREATE UNIQUE INDEX setting_pkey ON public.setting USING btree (id)`
  ---------------------------------------------------------------------------------------------------------------

### `student`

-   **Estimated rows:** 10

#### Columns

  ---------------------------------------------------------------------------------------------------------------
  Column                  Data type                    Nullable    Default               Identity    Identity
                                                                                                     generation
  ----------------------- ---------------------------- ----------- --------------------- ----------- ------------
  `id`                    `bigint`                     NO          ---                   YES         ALWAYS

  `institution_id`        `bigint`                     NO          ---                   NO          ---

  `program_id`            `bigint`                     NO          ---                   NO          ---

  `student_id`            `text`                       NO          ---                   NO          ---

  `apaar_id`              `text`                       NO          ---                   NO          ---

  `full_name`             `text`                       NO          ---                   NO          ---

  `dob`                   `text`                       NO          ---                   NO          ---

  `gender`                `text`                       NO          ---                   NO          ---

  `category`              `text`                       NO          `'GENERAL'::text`     NO          ---

  `admission_year`        `integer`                    NO          ---                   NO          ---

  `admission_type`        `text`                       NO          `'REGULAR'::text`     NO          ---

  `is_nri`                `boolean`                    NO          `false`               NO          ---

  `oci_status`            `boolean`                    NO          `false`               NO          ---

  `is_foreign_national`   `boolean`                    NO          `false`               NO          ---

  `nationality`           `text`                       NO          `'Indian'::text`      NO          ---

  `mode`                  `text`                       NO          `'FULL_TIME'::text`   NO          ---

  `status`                `text`                       NO          `'ACTIVE'::text`      NO          ---

  `consent_given`         `boolean`                    NO          `false`               NO          ---

  `consent_timestamp`     `timestamp with time zone`   YES         ---                   NO          ---

  `record_hash`           `text`                       YES         ---                   NO          ---

  `created_at`            `timestamp with time zone`   NO          `now()`               NO          ---

  `updated_at`            `timestamp with time zone`   NO          `now()`               NO          ---

  `consent_level`         `integer`                    NO          `1`                   NO          ---

  `record_signature`      `text`                       YES         ---                   NO          ---
  ---------------------------------------------------------------------------------------------------------------

#### Constraints

  ------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                  Type                    Definition
  ------------------------------------- ----------------------- ----------------------------------------------------------------------------------------
  `students_admission_type_check`       CHECK                   `CHECK ((admission_type = ANY (ARRAY['REGULAR'::text, 'SUPERNUMERARY'::text])))`

  `students_institution_id_fkey`        FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id)`

  `students_mode_check`                 CHECK                   `CHECK ((mode = ANY (ARRAY['FULL_TIME'::text, 'PART_TIME'::text])))`

  `students_pkey`                       PRIMARY KEY             `PRIMARY KEY (id)`

  `students_program_id_fkey`            FOREIGN KEY             `FOREIGN KEY (program_id) REFERENCES program(id)`

  `students_program_institution_fkey`   FOREIGN KEY             `FOREIGN KEY (program_id, institution_id) REFERENCES program(id, institution_id)`

  `students_status_check`               CHECK                   `CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'WITHDRAWN'::text, 'GRADUATED'::text])))`
  ------------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  ----------------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ----------------------------------------------------------------------------------------
  `idx_students_apaar`                `CREATE INDEX idx_students_apaar ON public.student USING btree (apaar_id)`

  `idx_students_institution`          `CREATE INDEX idx_students_institution ON public.student USING btree (institution_id)`

  `idx_students_program`              `CREATE INDEX idx_students_program ON public.student USING btree (program_id)`

  `students_pkey`                     `CREATE UNIQUE INDEX students_pkey ON public.student USING btree (id)`
  ----------------------------------------------------------------------------------------------------------------------------

### `user`

-   **Estimated rows:** 3

#### Columns

  --------------------------------------------------------------------------------------------------------------------------
  Column             Data type                    Nullable    Default                               Identity    Identity
                                                                                                                generation
  ------------------ ---------------------------- ----------- ------------------------------------- ----------- ------------
  `id`               `integer`                    NO          `nextval('users_id_seq'::regclass)`   NO          ---

  `username`         `character varying`          NO          ---                                   NO          ---

  `password_hash`    `character varying`          NO          ---                                   NO          ---

  `role`             `character varying`          NO          ---                                   NO          ---

  `institution_id`   `bigint`                     YES         ---                                   NO          ---

  `full_name`        `character varying`          NO          ---                                   NO          ---

  `apaar_id`         `text`                       YES         ---                                   NO          ---

  `created_at`       `timestamp with time zone`   NO          `now()`                               NO          ---
  --------------------------------------------------------------------------------------------------------------------------

#### Constraints

  -----------------------------------------------------------------------------------------------------------------
  Name                          Type                    Definition
  ----------------------------- ----------------------- -----------------------------------------------------------
  `users_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id)`

  `users_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`

  `users_username_key`          UNIQUE                  `UNIQUE (username)`
  -----------------------------------------------------------------------------------------------------------------

#### Indexes

  ----------------------------------------------------------------------------------------------------------------------
  Name                                Definition
  ----------------------------------- ----------------------------------------------------------------------------------
  `ix_user_apaar_id`                  `CREATE INDEX ix_user_apaar_id ON public."user" USING btree (apaar_id)`

  `ix_user_role`                      `CREATE INDEX ix_user_role ON public."user" USING btree (role)`

  `users_pkey`                        `CREATE UNIQUE INDEX users_pkey ON public."user" USING btree (id)`

  `users_username_key`                `CREATE UNIQUE INDEX users_username_key ON public."user" USING btree (username)`
  ----------------------------------------------------------------------------------------------------------------------

### `validationflag`

-   **Estimated rows:** 0

#### Columns

  ---------------------------------------------------------------------------------------------------------
  Column                 Data type                    Nullable    Default          Identity    Identity
                                                                                               generation
  ---------------------- ---------------------------- ----------- ---------------- ----------- ------------
  `id`                   `bigint`                     NO          ---              YES         ALWAYS

  `student_id`           `bigint`                     YES         ---              NO          ---

  `flag_type`            `text`                       NO          ---              NO          ---

  `severity`             `text`                       NO          `'HIGH'::text`   NO          ---

  `description`          `text`                       NO          ---              NO          ---

  `status`               `text`                       NO          `'OPEN'::text`   NO          ---

  `detected_at`          `timestamp with time zone`   NO          `now()`          NO          ---

  `resolved_at`          `timestamp with time zone`   YES         ---              NO          ---

  `resolved_by`          `text`                       YES         ---              NO          ---

  `institution_id`       `bigint`                     NO          ---              NO          ---

  `program_id`           `bigint`                     YES         ---              NO          ---

  `rule_code`            `text`                       NO          ---              NO          ---

  `message`              `text`                       NO          ---              NO          ---

  `created_at`           `timestamp with time zone`   NO          `now()`          NO          ---

  `recommended_action`   `text`                       NO          ---              NO          ---
  ---------------------------------------------------------------------------------------------------------

#### Constraints

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                     Type                    Definition
  ---------------------------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  `validation_flags_flag_type_check`       CHECK                   `CHECK ((flag_type = ANY (ARRAY['INVALID_APAAR_ID'::text, 'DUPLICATE_APAAR_ID'::text, 'NAME_MISMATCH'::text, 'DOB_MISMATCH'::text, 'REGISTRY_NOT_FOUND'::text, 'INSTITUTION_MISMATCH'::text])))`

  `validation_flags_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id)`

  `validation_flags_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`

  `validation_flags_program_id_fkey`       FOREIGN KEY             `FOREIGN KEY (program_id) REFERENCES program(id)`

  `validation_flags_severity_check`        CHECK                   `CHECK ((severity = ANY (ARRAY['INFO'::text, 'WARNING'::text, 'ERROR'::text])))`

  `validation_flags_status_check`          CHECK                   `CHECK ((status = ANY (ARRAY['OPEN'::text, 'RESOLVED'::text, 'IGNORED'::text])))`

  `validation_flags_student_id_fkey`       FOREIGN KEY             `FOREIGN KEY (student_id) REFERENCES student(id) ON DELETE CASCADE`
  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  --------------------------------------------------------------------------------------------------------------------------------------------
  Name                                 Definition
  ------------------------------------ -------------------------------------------------------------------------------------------------------
  `idx_validation_flags_status`        `CREATE INDEX idx_validation_flags_status ON public.validationflag USING btree (status)`

  `idx_validation_flags_student`       `CREATE INDEX idx_validation_flags_student ON public.validationflag USING btree (student_id)`

  `idx_validation_flags_type`          `CREATE INDEX idx_validation_flags_type ON public.validationflag USING btree (flag_type)`

  `ix_validationflag_institution_id`   `CREATE INDEX ix_validationflag_institution_id ON public.validationflag USING btree (institution_id)`

  `ix_validationflag_rule_code`        `CREATE INDEX ix_validationflag_rule_code ON public.validationflag USING btree (rule_code)`

  `validation_flags_pkey`              `CREATE UNIQUE INDEX validation_flags_pkey ON public.validationflag USING btree (id)`
  --------------------------------------------------------------------------------------------------------------------------------------------

### `verificationlog`

-   **Estimated rows:** 0

#### Columns

  ---------------------------------------------------------------------------------------------------------
  Column                Data type                    Nullable    Default           Identity    Identity
                                                                                               generation
  --------------------- ---------------------------- ----------- ----------------- ----------- ------------
  `id`                  `bigint`                     NO          ---               YES         ALWAYS

  `student_id`          `bigint`                     YES         ---               NO          ---

  `institution_id`      `bigint`                     YES         ---               NO          ---

  `requested_by`        `text`                       YES         ---               NO          ---

  `verification_type`   `text`                       NO          `'APAAR'::text`   NO          ---

  `result`              `text`                       NO          ---               NO          ---

  `message`             `text`                       YES         ---               NO          ---

  `checked_at`          `timestamp with time zone`   NO          `now()`           NO          ---

  `verifier_id`         `bigint`                     YES         ---               NO          ---

  `apaar_id`            `text`                       NO          ---               NO          ---

  `timestamp`           `timestamp with time zone`   NO          `now()`           NO          ---

  `tier_shown`          `integer`                    NO          `0`               NO          ---
  ---------------------------------------------------------------------------------------------------------

#### Constraints

  ------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                      Type                    Definition
  ----------------------------------------- ----------------------- ------------------------------------------------------------------------------------
  `verification_logs_institution_id_fkey`   FOREIGN KEY             `FOREIGN KEY (institution_id) REFERENCES institution(id) ON DELETE SET NULL`

  `verification_logs_pkey`                  PRIMARY KEY             `PRIMARY KEY (id)`

  `verification_logs_student_id_fkey`       FOREIGN KEY             `FOREIGN KEY (student_id) REFERENCES student(id) ON DELETE SET NULL`

  `verificationlog_result_check`            CHECK                   `CHECK ((result = ANY (ARRAY['VALID'::text, 'INVALID'::text, 'TAMPERED'::text])))`

  `verificationlog_verifier_id_fkey`        FOREIGN KEY             `FOREIGN KEY (verifier_id) REFERENCES "user"(id)`
  ------------------------------------------------------------------------------------------------------------------------------------------------------

#### Indexes

  -----------------------------------------------------------------------------------------------------------------------------------------------
  Name                                  Definition
  ------------------------------------- ---------------------------------------------------------------------------------------------------------
  `idx_verification_logs_checked_at`    `CREATE INDEX idx_verification_logs_checked_at ON public.verificationlog USING btree (checked_at DESC)`

  `idx_verification_logs_institution`   `CREATE INDEX idx_verification_logs_institution ON public.verificationlog USING btree (institution_id)`

  `idx_verification_logs_result`        `CREATE INDEX idx_verification_logs_result ON public.verificationlog USING btree (result)`

  `idx_verification_logs_student`       `CREATE INDEX idx_verification_logs_student ON public.verificationlog USING btree (student_id)`

  `ix_verificationlog_apaar_id`         `CREATE INDEX ix_verificationlog_apaar_id ON public.verificationlog USING btree (apaar_id)`

  `verification_logs_pkey`              `CREATE UNIQUE INDEX verification_logs_pkey ON public.verificationlog USING btree (id)`
  -----------------------------------------------------------------------------------------------------------------------------------------------

## Tables included in this snapshot

-   `anomalyalert`
-   `apaarregistry`
-   `auditlog`
-   `auditlog_legacy`
-   `institution`
-   `institution_api_keys`
-   `program`
-   `setting`
-   `student`
-   `user`
-   `validationflag`
-   `verificationlog`

------------------------------------------------------------------------

**Team note:** Treat this file as a reference snapshot. Before making
schema changes, compare it with the current `models.py` and run a fresh
export if the database has changed.
