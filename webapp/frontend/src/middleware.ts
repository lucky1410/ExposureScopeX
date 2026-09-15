import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Authentication is enforced by the API's HttpOnly session. The API runs on
  // a separate local origin, so its cookie is not reliably visible to Next.js
  // middleware even though browser API requests are authenticated.
  void pathname
  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
