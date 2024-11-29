CREATE TABLE IF NOT EXISTS "users" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"name" varchar(255) NOT NULL,
	"email" varchar(255) NOT NULL,
	"email_verified_at" timestamp,
	"password_hash" text,
	"password_salt" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "user_preferences" (
	"id" varchar PRIMARY KEY NOT NULL,
	"enabled_2fa" boolean DEFAULT false NOT NULL,
	"enabled_email_notification" boolean DEFAULT true NOT NULL,
	"two_factor_secret" text,
	"user_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "sessions" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"token" text NOT NULL,
	"user_agent" varchar(255),
	"last_used" timestamp,
	"expires_at" timestamp NOT NULL,
	"expires_in" integer NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "verifications_codes" (
	"id" varchar(50) PRIMARY KEY NOT NULL,
	"code" text NOT NULL,
	"user_id" varchar(50) NOT NULL,
	"expired_at" timestamp NOT NULL,
	"type" varchar NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "user_preferences" ADD CONSTRAINT "user_preferences_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "verifications_codes" ADD CONSTRAINT "verifications_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
