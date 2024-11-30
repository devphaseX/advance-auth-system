// Looking to send emails in production? Check out our Email API/SMTP product!
import Nodemailer from "nodemailer";
import { Address, MailtrapTransport } from "mailtrap";
import { getEnv } from "config/env";
import { SendMailProps } from "./mailer";

const transport = Nodemailer.createTransport(
  MailtrapTransport({
    token: getEnv("MAIL_TRAP_API_KEY"),
    testInboxId: 2350607,
    accountId: Number(getEnv("MAIL_TRAP_ACCOUNT_ID")),
  }),
);

export function sendMailWithTransport(props: SendMailProps) {
  const sender = props.from ?? {
    name: getEnv("MAIL_SENDER_NAME"),
    email: getEnv("MAIL_SENDER_EMAIL"),
  };

  return transport.sendMail({
    ...props,
    //@ts-ignore
    from: sender!,
    sandbox: true,
  });
}
