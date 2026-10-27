import {
  Activity,
  AppWindow,
  Bell,
  BadgeCheck,
  Bot,
  EyeOff,
  FileText,
  Gauge,
  LayoutDashboard,
  List,
  type LucideIcon,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
} from "lucide-react";
import type { Me } from "../api/client";

export interface NavItem {
  path: string;
  title: string;
  icon: LucideIcon;
  stage4?: boolean;
  // Видно, если есть любое из прав; без списка — видно всем. Права проверяет сервер, консоль только скрывает.
  anyOf?: string[];
}

// Разделы по ТЗ 6.3. Право на раздел задано, когда оно уже есть в модели RBAC.
export const navItems: NavItem[] = [
  { path: "/", title: "Обзор", icon: LayoutDashboard, anyOf: ["dashboards.read"] },
  { path: "/events", title: "События", icon: List, anyOf: ["events.read"] },
  { path: "/alerts", title: "Оповещения", icon: Bell, anyOf: ["alerts.read"] },
  { path: "/incidents", title: "Инциденты", icon: ShieldAlert, anyOf: ["incidents.read"] },
  { path: "/apps", title: "Приложения", icon: AppWindow, anyOf: ["applications.read"] },
  { path: "/providers", title: "Провайдеры", icon: Server, anyOf: ["providers.read"] },
  { path: "/policies", title: "Политики", icon: ScrollText, anyOf: ["policies.read"] },
  { path: "/usage", title: "Потребление", icon: Gauge, anyOf: ["dashboards.read"] },
  { path: "/agents", title: "Агенты", icon: Bot, stage4: true },
  { path: "/shadow-ai", title: "Теневой ИИ", icon: EyeOff, stage4: true },
  { path: "/compliance", title: "Соответствие", icon: BadgeCheck, stage4: true },
  { path: "/reports", title: "Отчёты", icon: FileText, anyOf: ["reports.read"] },
  {
    path: "/admin",
    title: "Администрирование",
    icon: Settings,
    anyOf: ["users.read", "roles.read", "sessions.read", "auth_policy.read", "auth_idp.read", "api_tokens.read"],
  },
  { path: "/system", title: "Состояние системы", icon: Activity, anyOf: ["system.read"] },
];

export function visibleNav(me: Me): NavItem[] {
  return navItems.filter((i) => !i.anyOf || i.anyOf.some((p) => me.permissions.includes(p)));
}
