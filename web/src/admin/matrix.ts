import type { Permission, RoleDetails } from "./api";

export type Cell = "all" | "own" | null;

export interface MatrixGroup {
  group: string;
  rows: { permission: Permission; cells: Cell[] }[];
}

// Матрица «разрешение × роль» строится из ответов GET /permissions и GET /roles, без своего списка.
// Разрешения session и self сессия добавляет сама, в ролях их нет — в матрицу они не входят.
export function buildMatrix(permissions: Permission[], roles: RoleDetails[]): MatrixGroup[] {
  const granted = roles.map((r) => new Map(r.permissions.map((g) => [g.permission, g.scope])));
  const groups = new Map<string, MatrixGroup>();
  for (const p of permissions) {
    let g = groups.get(p.group);
    if (!g) {
      g = { group: p.group, rows: [] };
      groups.set(p.group, g);
    }
    g.rows.push({ permission: p, cells: granted.map((m) => m.get(p.name) ?? null) });
  }
  return [...groups.values()];
}

// Роль, которую пользователь может выдать: все её разрешения входят в его права (УПД.2).
// Решение всегда за сервером; здесь только подсказка, чтобы не предлагать заведомо отказ.
export function assignable(role: RoleDetails, mine: ReadonlySet<string>): boolean {
  return role.permissions.every((g) => mine.has(g.permission));
}
