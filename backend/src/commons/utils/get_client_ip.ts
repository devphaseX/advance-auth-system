import { Context } from "hono";
import { isIP } from "net";
import { Hono } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";

const isValidIP = (ip: string) => isIP(ip) === 4 || isIP(ip) === 6;

const handleArray = (results: Array<string>) => {
  if (!results) return null;
  if (!Array.isArray(results)) return null;
  if (results.length === 0) return null;
  const ips = results.filter(
    (ip) => typeof ip === "string" && isValidIP(ip.trim()),
  );
  if (ips.length > 0) {
    console.log("ips", ips);
    return ips[0].trim();
  }
  return null;
};

const handleResults = (results: string | string[]) => {
  if (!results) return null;
  if (Array.isArray(results)) {
    const ip = handleArray(results);
    if (ip) return ip;
  }
  if (typeof results === "string") {
    if (results.includes(",")) {
      const ip = handleArray(results.split(","));
      if (ip) return ip;
    }
    if (isValidIP(results)) return results;
  }
  return null;
};

const customHeaders = [
  "x-client-ip",
  "x-forwarded-for",
  "forwarded-for",
  "x-forwarded",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
  "x-cluster-client-ip",
  "fastly-client-ip",
  "x-appengine-user-ip",
  "Cf-Pseudo-IPv4",
];

const getIPFromHeaders = (c: Context) => {
  //Validate headers
  //looking for the first IP header req.headers.forwarded
  const reqForwarded = c.req.header("forwarded");
  if (reqForwarded && typeof reqForwarded === "string") {
    const ip = handleResults(reqForwarded);
    if (ip) return ip;
  }
  //Looking through each custom header and returns the valid one
  for (const customHeader of customHeaders) {
    if (c.req.header(customHeader)) {
      const ip = handleResults(c.req.header(customHeader)!);
      if (ip) return ip;
    }
  }
  return null;
};

const getClientIp = (c: Context) => {
  //Validate request
  //Getting IP from headers
  const ip = getIPFromHeaders(c);
  if (ip) return ip;
  //Getting IP from socket
  const {
    remote: { address },
  } = getConnInfo(c);

  if (address) {
    if (isValidIP(address)) return address;
  }
  return null;
};

export { getClientIp as default };
