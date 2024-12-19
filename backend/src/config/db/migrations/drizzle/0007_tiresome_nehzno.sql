CREATE TABLE IF NOT EXISTS "password_reset_session" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"expired_at" timestamp NOT NULL,
	"email" varchar(255) NOT NULL,
	"code" text,
	"email_verified" boolean,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "api_keys" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"name" varchar(50) NOT NULL,
	"prefix" varchar(255) NOT NULL,
	"hash" text NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"scopes" jsonb,
	"user_id" varchar,
	"last_used_at" timestamp with time zone,
	"expires_in" integer,
	"expired_at" timestamp with time zone,
	"replaced_by_key_id" varchar(50),
	"rotation_window_ends" timestamp with time zone,
	"deleted_at" timestamp with time zone,
	"deleted_reason" varchar(255),
	"deleted_by" varchar(50),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "ip" varchar(20);--> statement-breakpoint
ALTER TABLE "verifications_codes" ADD COLUMN "metadata" jsonb;--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "password_reset_session" ADD CONSTRAINT "password_reset_session_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
