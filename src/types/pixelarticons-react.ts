/* src/types/pixelarticons-react.ts
 * Copyright (c) 2026 Clove Nytrix Doughmination Twilight
 * Licensed under the DASL-1.2 Licence.
 * See LICENCE.md in the project root for full licence information.
 *
 * Type-checking stand-in for `pixelarticons/react`. Its real .d.ts types each
 * icon as a React component; tsconfig.json points the "pixelarticons/react"
 * specifier here instead so tsc checks against what these actually are at
 * runtime under the `react` -> `hono/jsx` alias in wrangler.jsonc. Add a line
 * here whenever a new icon from the package is imported.
 */

type Icon = (props: Record<string, unknown>) => any;

export declare const AppWindows: Icon;
export declare const ArrowLeft: Icon;
export declare const Key: Icon;
export declare const Link: Icon;
export declare const Login: Icon;
export declare const Logout: Icon;
export declare const Save: Icon;
export declare const Shield: Icon;
export declare const User: Icon;
export declare const UserPlus: Icon;
export declare const Users: Icon;
