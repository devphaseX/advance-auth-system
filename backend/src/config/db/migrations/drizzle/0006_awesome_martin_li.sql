CREATE VIEW "public"."public_user_preferences" AS (select "id", "enabled_2fa", "enabled_email_notification", "user_id", "created_at", "updated_at" from "user_preferences");