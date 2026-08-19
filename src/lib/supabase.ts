import { createClient } from "@supabase/supabase-js";

/* createClient throws on an empty URL, and this module is imported from the
 * app's entry graph — an unconfigured build therefore threw before React could
 * mount and the window came up completely blank, with the real cause visible
 * only in the developer console. Fall back to a syntactically valid placeholder
 * so the app always renders and only sign-in is affected. */
const PLACEHOLDER_URL = "https://unconfigured.supabase.co";
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || PLACEHOLDER_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || "unconfigured";

export const isSupabaseConfigured =
  !!import.meta.env.VITE_SUPABASE_URL && !!import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    /* PKCE is what allows the code returned to the loopback listener to be
     * exchanged for a session inside the app. */
    flowType: "pkce",
    /* The desktop app is never navigated to the callback URL itself, so there
     * is nothing in the address bar to detect. */
    detectSessionInUrl: false,
    persistSession: true,
    autoRefreshToken: true,
  },
});

/**
 * Begin Google sign-in.
 *
 * On desktop the provider URL is returned rather than followed: Google rejects
 * OAuth attempts from embedded webviews, so the caller opens it in the user's
 * real browser and waits for the loopback listener to hand back a code.
 */
export async function signInWithGoogle(redirectTo: string) {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: { redirectTo, skipBrowserRedirect: true },
  });
  if (error) throw error;
  if (!data?.url) throw new Error("Supabase did not return an authorization URL");
  return data.url;
}

/** Exchange the authorization code from the loopback listener for a session. */
export async function completeSignIn(code: string) {
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) throw error;
}

export async function getSession() {
  const { data } = await supabase.auth.getSession();
  return data.session;
}

export async function signOut() {
  await supabase.auth.signOut();
}
