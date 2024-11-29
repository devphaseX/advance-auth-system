ALTER TABLE "sessions" ALTER COLUMN "id" SET DATA TYPE varchar(255);--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN IF EXISTS "expires_in";