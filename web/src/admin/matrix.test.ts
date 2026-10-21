import { describe, expect, it } from "vitest";
import type { Permission, RoleDetails } from "./api";
import { assignable, buildMatrix } from "./matrix";

const perm = (name: string, group: string, security = false): Permission => ({ name, title: name, group, security, ownable: false });
const role = (id: string, grants: [string, "all" | "own"][]): RoleDetails => ({
  id,
  display_name: id,
  description: "",
  builtin: false,
  mfa_required: false,
  users: 0,
  permissions: grants.map(([permission, scope]) => ({ permission, scope })),
});

describe("матрица разрешений", () => {
  it("строится из каталога и ролей, без своего списка", () => {
    const m = buildMatrix(
      [perm("users.read", "Пользователи"), perm("users.manage", "Пользователи"), perm("events.read", "События")],
      [role("a", [["users.read", "all"], ["events.read", "own"]]), role("b", [])],
    );
    expect(m.map((g) => g.group)).toEqual(["Пользователи", "События"]);
    expect(m[0]!.rows.map((r) => r.cells)).toEqual([
      ["all", null],
      [null, null],
    ]);
    expect(m[1]!.rows[0]!.cells).toEqual(["own", null]);
  });

  it("пустые каталог и роли дают пустую матрицу", () => {
    expect(buildMatrix([], [])).toEqual([]);
    expect(buildMatrix([perm("x", "g")], [])[0]!.rows[0]!.cells).toEqual([]);
  });

  it("роль выдаётся, если все её права есть у назначающего", () => {
    const mine = new Set(["users.read", "events.read"]);
    expect(assignable(role("a", [["users.read", "all"]]), mine)).toBe(true);
    expect(assignable(role("b", [["users.read", "all"], ["roles.manage", "all"]]), mine)).toBe(false);
    expect(assignable(role("c", []), mine)).toBe(true);
  });
});
