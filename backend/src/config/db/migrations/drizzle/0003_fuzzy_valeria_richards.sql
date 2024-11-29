ALTER TABLE "sessions" ALTER COLUMN "id" SET DATA TYPE varchar(50);--> statement-breakpoint
ALTER TABLE "sessions" DROP COLUMN IF EXISTS "token";