import { QueryClient, QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, setUnauthorizedHandler } from "./api/client";
import { Login } from "./auth/Login";
import { MfaSetup } from "./auth/MfaSetup";
import { MfaVerify } from "./auth/MfaVerify";
import { PasswordChange } from "./auth/PasswordChange";
import { Setup } from "./auth/Setup";
import { Shell } from "./shell/Shell";
import { Banner } from "./ui/Layout";

export function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false, staleTime: 30_000 } } });
}

// Выбор экрана по состоянию сессии из /api/v1/me (ТЗ 6.4): права проверяет сервер.
function Gate() {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: ({ signal }) => api.me(signal) });
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: ({ signal }) => api.setupStatus(signal),
    enabled: me.isSuccess && me.data === null,
  });
  const [created, setCreated] = useState(false);

  // 401 на любом запросе консоли — назад ко входу.
  useEffect(() => {
    setUnauthorizedHandler(() => qc.setQueryData(["me"], null));
    return () => setUnauthorizedHandler(undefined);
  }, [qc]);

  const logout = useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => {
      qc.clear();
      qc.setQueryData(["me"], null);
    },
  });

  if (me.isPending || (me.data === null && setup.isPending)) return null;
  if (me.isError) {
    return (
      <main className="mx-auto max-w-sm p-8">
        <Banner kind="error">Сервер не отвечает. Обновите страницу или обратитесь к администратору.</Banner>
      </main>
    );
  }
  const data = me.data;
  if (!data) {
    if (setup.data?.setup_required) return <Setup onDone={() => setCreated(true)} />;
    return (
      <>
        {created && (
          <div className="mx-auto max-w-sm px-4 pt-6">
            <Banner kind="info">Администратор создан. Войдите под его логином.</Banner>
          </div>
        )}
        <Login />
      </>
    );
  }
  const out = () => logout.mutate();
  switch (data.session_state) {
    case "mfa_pending":
      return <MfaVerify onCancel={out} />;
    case "mfa_setup":
      return <MfaSetup onCancel={out} />;
    case "password_change":
      return <PasswordChange onCancel={out} />;
    default:
      return <Shell me={data} onLogout={out} />;
  }
}

export function App({ client }: { client?: QueryClient }) {
  const [qc] = useState(() => client ?? makeQueryClient());
  return (
    <QueryClientProvider client={qc}>
      <Gate />
    </QueryClientProvider>
  );
}
