/* src/views/layout.tsx
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 */

import type { Child } from "hono/jsx";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { siteName, type AppContext } from "../env";

interface PageOptions {
  title: string;
  /** Picks the behaviour in /static/app.js. */
  page?: string;
  /** Centered card layout for sign-in screens. */
  narrow?: boolean;
  status?: ContentfulStatusCode;
}

export async function render(c: AppContext, opts: PageOptions, body: Child): Promise<Response> {
  const site = siteName(c.env);
  const user = c.get("user");
  const session = c.get("session");

  const html = (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="dark light" />
        <meta name="robots" content="noindex" />
        <title>{`${opts.title} · ${site}`}</title>
        <link rel="stylesheet" href="/static/style.css" />
        <script src="/static/app.js" defer></script>
      </head>
      <body data-page={opts.page ?? ""} data-csrf={session?.csrf ?? ""}>
        <header class="topbar">
          <a class="brand" href={user ? "/account" : "/login"}>
            {site}
          </a>
          {user && (
            <nav>
              <a href="/account">Account</a>
              {user.isAdmin && <a href="/admin">Admin</a>}
              <form method="post" action="/logout" class="inline">
                <input type="hidden" name="_csrf" value={session?.csrf ?? ""} />
                <button type="submit" class="link">
                  Sign out
                </button>
              </form>
            </nav>
          )}
        </header>
        <main class={opts.narrow ? "narrow" : "wide"}>{body}</main>
      </body>
    </html>
  );

  return c.html(`<!doctype html>${await html}`, opts.status ?? 200);
}
