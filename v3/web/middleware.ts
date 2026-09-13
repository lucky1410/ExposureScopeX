import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const authenticated = request.cookies.has("esx_session");
  const login = request.nextUrl.pathname === "/login";
  if (!authenticated && !login) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
