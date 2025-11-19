import fs from "node:fs";
import path from "node:path";
import type { VercelRequest, VercelResponse } from "@vercel/node";
import verifyHandler from "./verify";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Only handle GET requests (POST should go directly to /api/verify)
  if (req.method !== "GET") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  // Check if client wants JSON (API client)
  const accept = (req.headers["accept"] || "").toString().toLowerCase();
  const wantsJson = accept.includes("application/json");

  // API clients requesting JSON get the verify handler
  if (wantsJson) {
    return verifyHandler(req, res);
  }

  // Browsers get the HTML page
  const indexPath = path.join(process.cwd(), "public", "index.html");
  let html: string;

  try {
    html = fs.readFileSync(indexPath, "utf8");
  } catch (e) {
    res.status(500).send("index.html not found");
    return;
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(html);
}

