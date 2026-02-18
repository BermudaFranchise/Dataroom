import { createHash } from "crypto";

const TOKEN_HASH_PURPOSE_SALT = "bf-fund-token-hash-v1";

export const hashToken = (
  token: string,
  {
    noSecret = false,
  }: {
    noSecret?: boolean;
  } = {},
) => {
  const secret = noSecret ? "" : `${process.env.NEXTAUTH_SECRET}:${TOKEN_HASH_PURPOSE_SALT}`;
  return createHash("sha256")
    .update(`${token}${secret}`)
    .digest("hex");
};
