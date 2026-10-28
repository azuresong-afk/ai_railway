import { Keyboard, LogOut, Maximize2, PanelLeft, Search, X } from "lucide-react";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { HashRouter, NavLink, Route, Routes, useLocation, useNavigate, useSearchParams } from "react-router";
import type { Me } from "../api/client";
import { Button } from "../ui/Button";
import { Input, Select } from "../ui/Field";
import { EmptyState } from "../ui/Layout";
import { Modal } from "../ui/Overlay";
import { navItems, visibleNav } from "./nav";

type Theme = "auto" | "light" | "dark";

const hotkeys: [string, string][] = [
  ["/", "перейти к поиску"],
  ["g, затем e", "события"],
  ["g, затем i", "инциденты"],
  ["?", "эта справка"],
];

function useTheme(): [Theme, (t: Theme) => void] {
  // Выбор темы живёт только в памяти страницы: хранилища браузера консоль не использует.
  const [theme, setTheme] = useState<Theme>("auto");
  useEffect(() => {
    const el = document.documentElement;
    if (theme === "auto") el.removeAttribute("data-theme");
    else el.setAttribute("data-theme", theme);
  }, [theme]);
  return [theme, setTheme];
}

function isTyping(t: EventTarget | null): boolean {
  return t instanceof HTMLElement && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));
}

// Выдвижная панель справа: состояние в адресе (?panel=...), поэтому на неё есть прямая ссылка.
function SidePanel() {
  const [params, setParams] = useSearchParams();
  const id = params.get("panel");
  const [full, setFull] = useState(false);
  if (!id) return null;
  const close = () => {
    const next = new URLSearchParams(params);
    next.delete("panel");
    setParams(next);
  };
  return (
    <aside
      aria-label="Детали"
      className={`${full ? "fixed inset-0 z-40" : "w-96 shrink-0"} flex flex-col gap-3 border-l border-line bg-surface p-4`}
    >
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Детали</h2>
        <div className="flex gap-1">
          <Button variant="ghost" aria-label={full ? "Свернуть панель" : "Развернуть панель на весь экран"} onClick={() => setFull(!full)}>
            <Maximize2 size={16} aria-hidden="true" />
          </Button>
          <Button variant="ghost" aria-label="Закрыть панель" onClick={close}>
            <X size={16} aria-hidden="true" />
          </Button>
        </div>
      </div>
      <p className="text-sm text-muted">Здесь откроются подробности выбранной записи.</p>
    </aside>
  );
}

function Stub() {
  const { pathname } = useLocation();
  const item = navItems.find((i) => i.path === pathname);
  return (
    <EmptyState
      title={`${item?.title ?? "Раздел"}: раздел в разработке`}
      action={<p className="text-sm text-muted">Экран появится в одной из следующих задач этапа.</p>}
    />
  );
}

// Экран загружается отдельным куском (ТЗ 6.8: разделение кода по маршрутам).
const EventsScreen = lazy(() => import("../events/EventsScreen").then((m) => ({ default: m.EventsScreen })));

function EventsRoute({ me }: { me: Me }) {
  if (!me.permissions.includes("events.read")) {
    return <EmptyState title="Нет доступа к событиям" action={<p className="text-sm text-muted">Обратитесь к администратору.</p>} />;
  }
  return (
    <Suspense fallback={null}>
      <EventsScreen me={me} />
    </Suspense>
  );
}

const AppsScreen = lazy(() => import("../apps/AppsScreen").then((m) => ({ default: m.AppsScreen })));
const AlertsScreen = lazy(() => import("../alerts/AlertsScreen").then((m) => ({ default: m.AlertsScreen })));
const IncidentsScreen = lazy(() => import("../incidents/IncidentsScreen").then((m) => ({ default: m.IncidentsScreen })));
const ProvidersScreen = lazy(() => import("../providers/ProvidersScreen").then((m) => ({ default: m.ProvidersScreen })));
const AgentsScreen = lazy(() => import("../agents/AgentsScreen").then((m) => ({ default: m.AgentsScreen })));
const SessionScreen = lazy(() => import("../agents/SessionScreen").then((m) => ({ default: m.SessionScreen })));
const ApprovalsScreen = lazy(() => import("../approvals/ApprovalsScreen").then((m) => ({ default: m.ApprovalsScreen })));
const PoliciesScreen = lazy(() => import("../policies/PoliciesScreen").then((m) => ({ default: m.PoliciesScreen })));

function GuardedRoute({ me, perm, title, children }: { me: Me; perm: string; title: string; children: React.ReactNode }) {
  if (!me.permissions.includes(perm)) {
    return <EmptyState title={`Нет доступа: ${title}`} action={<p className="text-sm text-muted">Обратитесь к администратору.</p>} />;
  }
  return <Suspense fallback={null}>{children}</Suspense>;
}

const DashboardsScreen = lazy(() => import("../dashboards/DashboardsScreen").then((m) => ({ default: m.DashboardsScreen })));
const UsageScreen = lazy(() => import("../consumption/UsageScreen").then((m) => ({ default: m.UsageScreen })));

const ReportsScreen = lazy(() => import("../reports/ReportsScreen").then((m) => ({ default: m.ReportsScreen })));
const AdminScreen = lazy(() => import("../admin/AdminScreen").then((m) => ({ default: m.AdminScreen })));
const SystemScreen = lazy(() => import("../system/SystemScreen").then((m) => ({ default: m.SystemScreen })));
const ProfileScreen = lazy(() => import("../profile/ProfileScreen").then((m) => ({ default: m.ProfileScreen })));

function SystemRoute({ me }: { me: Me }) {
  if (!me.permissions.includes("system.read")) {
    return <EmptyState title="Нет доступа к состоянию системы" action={<p className="text-sm text-muted">Обратитесь к администратору.</p>} />;
  }
  return (
    <Suspense fallback={null}>
      <SystemScreen me={me} />
    </Suspense>
  );
}

function AdminRoute({ me }: { me: Me }) {
  return (
    <Suspense fallback={null}>
      <AdminScreen me={me} />
    </Suspense>
  );
}

function Frame({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useTheme();
  const nav = useNavigate();
  const search = useRef<HTMLInputElement>(null);
  const help = useRef<HTMLButtonElement>(null);
  const items = visibleNav(me);

  useEffect(() => {
    let g = 0;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target)) return;
      const armed = Date.now() - g < 1500;
      g = 0;
      if (e.key === "/") {
        e.preventDefault();
        search.current?.focus();
      } else if (e.key === "?") {
        help.current?.click();
      } else if (e.key === "g") {
        g = Date.now();
      } else if (armed && e.key === "e") {
        nav("/events");
      } else if (armed && e.key === "i") {
        nav("/incidents");
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [nav]);

  return (
    <div className="flex h-screen">
      <nav aria-label="Разделы" className={`${collapsed ? "w-14" : "w-60"} flex shrink-0 flex-col gap-1 border-r border-line bg-surface p-2`}>
        <div className="flex items-center justify-between px-1 pb-2">
          {!collapsed && <span className="text-lg font-semibold">AISec</span>}
          <Button
            variant="ghost"
            aria-label={collapsed ? "Развернуть панель разделов" : "Свернуть панель разделов"}
            aria-expanded={!collapsed}
            onClick={() => setCollapsed(!collapsed)}
          >
            <PanelLeft size={16} aria-hidden="true" />
          </Button>
        </div>
        {items.map((i) => (
          <NavLink
            key={i.path}
            to={i.path}
            end
            title={collapsed ? i.title : undefined}
            aria-label={collapsed ? i.title : undefined}
            className={({ isActive }) =>
              `flex h-[var(--control-h)] items-center gap-2 rounded-control px-2 text-base hover:bg-surface-hover ${isActive ? "bg-surface-hover font-medium text-fg" : "text-muted"}`
            }
          >
            <i.icon size={16} aria-hidden="true" className="shrink-0" />
            {!collapsed && <span className="truncate">{i.title}</span>}
            {!collapsed && i.stage4 && <span className="ml-auto text-xs text-muted">этап 4</span>}
          </NavLink>
        ))}
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-surface px-4 py-2">
          <div className="relative max-w-sm flex-1">
            <Search size={16} aria-hidden="true" className="absolute top-1/2 left-2 -translate-y-1/2 text-muted" />
            <Input
              ref={search}
              disabled
              aria-label="Поиск по ID события, приложению, пользователю"
              placeholder="Поиск: «/» (скоро)"
              className="pl-8"
            />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Modal
              title="Горячие клавиши"
              trigger={
                <Button ref={help} variant="ghost" aria-label="Горячие клавиши">
                  <Keyboard size={16} aria-hidden="true" />
                </Button>
              }
            >
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-base">
                {hotkeys.map(([k, d]) => (
                  <div key={k} className="contents">
                    <dt className="font-mono text-sm">{k}</dt>
                    <dd>{d}</dd>
                  </div>
                ))}
              </dl>
            </Modal>
            <label className="flex items-center gap-2 text-sm text-muted">
              Тема
              <Select value={theme} onChange={(e) => setTheme(e.target.value as Theme)} className="w-32">
                <option value="auto">Как в системе</option>
                <option value="light">Светлая</option>
                <option value="dark">Тёмная</option>
              </Select>
            </label>
            <NavLink to="/profile" className="text-sm underline" aria-label="Профиль">
              {me.user.display_name}
            </NavLink>
            <Button variant="ghost" onClick={onLogout}>
              <LogOut size={16} aria-hidden="true" />
              Выйти
            </Button>
          </div>
        </header>
        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-auto p-6">
            <Routes>
              <Route path="/" element={<GuardedRoute me={me} perm="dashboards.read" title="обзор"><DashboardsScreen me={me} /></GuardedRoute>} />
              <Route path="/usage" element={<GuardedRoute me={me} perm="dashboards.read" title="потребление"><UsageScreen me={me} /></GuardedRoute>} />
              <Route path="/events" element={<EventsRoute me={me} />} />
              <Route path="/apps" element={<GuardedRoute me={me} perm="applications.read" title="приложения"><AppsScreen me={me} /></GuardedRoute>} />
              <Route path="/alerts" element={<GuardedRoute me={me} perm="alerts.read" title="оповещения"><AlertsScreen me={me} /></GuardedRoute>} />
              <Route path="/incidents" element={<GuardedRoute me={me} perm="incidents.read" title="инциденты"><IncidentsScreen me={me} /></GuardedRoute>} />
              <Route path="/providers" element={<GuardedRoute me={me} perm="providers.read" title="провайдеры"><ProvidersScreen me={me} /></GuardedRoute>} />
              <Route path="/agents" element={<GuardedRoute me={me} perm="agents.read" title="агенты"><AgentsScreen me={me} /></GuardedRoute>} />
              <Route path="/approvals" element={<GuardedRoute me={me} perm="approvals.read" title="подтверждения"><ApprovalsScreen me={me} /></GuardedRoute>} />
              <Route path="/session/:id" element={<GuardedRoute me={me} perm="events.read" title="хронология сессии"><SessionScreen me={me} /></GuardedRoute>} />
              <Route path="/policies" element={<GuardedRoute me={me} perm="policies.read" title="политики"><PoliciesScreen me={me} /></GuardedRoute>} />
              <Route path="/reports" element={<GuardedRoute me={me} perm="reports.read" title="отчёты"><ReportsScreen me={me} /></GuardedRoute>} />
              <Route path="/profile" element={<ProfileScreen me={me} />} />
              <Route path="/admin" element={<AdminRoute me={me} />} />
              <Route path="/system" element={<SystemRoute me={me} />} />
              <Route path="*" element={<Stub />} />
            </Routes>
          </main>
          <SidePanel />
        </div>
      </div>
    </div>
  );
}

export function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  return (
    <HashRouter>
      <Frame me={me} onLogout={onLogout} />
    </HashRouter>
  );
}
