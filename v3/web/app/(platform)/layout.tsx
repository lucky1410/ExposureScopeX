import { ReactNode } from "react";

import AppShell from "../../components/AppShell";

export default function PlatformLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
