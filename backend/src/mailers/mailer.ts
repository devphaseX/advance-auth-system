import { AppEnv } from "@/commons/enums/env.enum";
import { getEnv } from "config/env";
import { Address, Mail, MailtrapClient } from "mailtrap";

const client = new MailtrapClient({
  token: getEnv("MAIL_TRAP_API_KEY"),
  accountId: Number(getEnv("MAIL_TRAP_ACCOUNT_ID")),
  ...(getEnv("NODE_ENV") === AppEnv.DEVELOPMENT
    ? { testInboxId: 2350607 }
    : null),
});

export type SendMailProps = Omit<Mail, "from"> & { from?: Address };
export function sendMail(props: SendMailProps) {
  const sender: Address = props.from ?? {
    name: getEnv("MAIL_SENDER_NAME"),
    email: getEnv("MAIL_SENDER_EMAIL"),
  };

  return getEnv("NODE_ENV") === AppEnv.DEVELOPMENT
    ? client.testing.send({ ...props, from: sender } as Mail)
    : client.send({ ...props, from: sender } as Mail);
}
