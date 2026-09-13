export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
export const EVALUATOR_ORGANIZATION_STORAGE_KEY = "esx.evaluator.organization";

export function setEvaluatorOrganization(organizationId: string | null) {
  if (typeof window === "undefined") return;
  if (organizationId) {
    window.localStorage.setItem(EVALUATOR_ORGANIZATION_STORAGE_KEY, organizationId);
  } else {
    window.localStorage.removeItem(EVALUATOR_ORGANIZATION_STORAGE_KEY);
  }
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const evaluatorOrganization = typeof window === "undefined"
    ? null
    : window.localStorage.getItem(EVALUATOR_ORGANIZATION_STORAGE_KEY);
  return fetch(`${API}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(evaluatorOrganization ? { "X-ESX-Organization": evaluatorOrganization } : {}),
      ...init.headers,
    },
  });
}
