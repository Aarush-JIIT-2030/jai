import { supabase } from "./supabase";

export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (supabase) {
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) headers.set("Authorization", `Bearer ${session.access_token}`);
  }
    const apiBase = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");
  if (import.meta.env.PROD && !apiBase) {
    throw new Error("Backend URL is not configured. Set VITE_API_BASE_URL to the deployed CyberSentinel API URL in Vercel.");
  }
  const target = typeof input === "string" && input.startsWith("/") ? `${apiBase}${input}` : input;
  return fetch(target, { ...init, headers });
}

export async function downloadAuthenticatedFile(path: string, filename: string): Promise<void> {
  const response = await apiFetch(path);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(String(payload.detail?.message ?? payload.detail ?? `${filename} is unavailable.`));
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
