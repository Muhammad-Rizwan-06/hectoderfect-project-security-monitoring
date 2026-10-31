import { readFile } from "node:fs/promises";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const DEVNET_RPC_URL = "https://api.devnet.solana.com";
const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

function isSecretKeyBytes(value: unknown): value is number[] {
  return (
    Array.isArray(value) &&
    value.length === 64 &&
    value.every((byte): byte is number => Number.isInteger(byte) && byte >= 0 && byte <= 255)
  );
}

export interface SolanaReceipt {
  network: "devnet";
  reportSha256: string;
  wallet: string;
  signature: string;
  explorerUrl: string;
}

export async function submitDevnetReceipt(reportSha256: string): Promise<SolanaReceipt> {
  const keypairPath = process.env.SOLANA_KEYPAIR_PATH?.trim();
  if (!keypairPath) throw new Error("Set SOLANA_KEYPAIR_PATH to a local Solana Devnet keypair JSON file.");
  if (!/^[a-f0-9]{64}$/.test(reportSha256)) throw new Error("Report digest must be a SHA-256 hex string.");

  let secret: unknown;
  try {
    secret = JSON.parse(await readFile(keypairPath, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`Could not read the configured Solana keypair file: ${errorMessage(error)}`);
  }
  if (!isSecretKeyBytes(secret)) {
    throw new Error("The Solana keypair file must contain a JSON array of 64 byte values.");
  }

  const keypair = await Keypair.fromSecretKey(Uint8Array.from(secret));
  const connection = new Connection(DEVNET_RPC_URL, "confirmed");
  const instruction = new TransactionInstruction({
    keys: [],
    programId: MEMO_PROGRAM_ID,
    data: Buffer.from(`depguard:v1:sha256:${reportSha256}`, "utf8"),
  });
  let signature: string;
  try {
    signature = await sendAndConfirmTransaction(
      connection,
      new Transaction().add(instruction),
      [keypair],
      { commitment: "confirmed", preflightCommitment: "confirmed" },
    );
  } catch (error) {
    throw new Error(`Solana Devnet receipt submission failed: ${errorMessage(error)}`);
  }

  return {
    network: "devnet",
    reportSha256,
    wallet: keypair.address,
    signature,
    explorerUrl: `https://explorer.solana.com/tx/${signature}?cluster=devnet`,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
