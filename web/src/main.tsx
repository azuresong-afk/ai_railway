import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

// Страницы разработки (макет Radix, ui-kit) есть только в dev-сборке и сборке e2e
// (vite --mode e2e); в продуктовую сборку они не попадают: условие вычисляется при сборке.
const devPages = import.meta.env.DEV || import.meta.env.MODE === "e2e";
const RadixMockup = devPages
  ? lazy(() => import("./dev/RadixMockup").then((m) => ({ default: m.RadixMockup })))
  : null;
const UiKit = devPages ? lazy(() => import("./dev/UiKit").then((m) => ({ default: m.UiKit }))) : null;

function Page() {
  if (RadixMockup && location.hash === "#/dev/radix") return <RadixMockup />;
  if (UiKit && location.hash === "#/dev/ui-kit") return <UiKit />;
  return <App />;
}

const root = document.getElementById("root");
if (!root) {
  throw new Error("Нет элемента #root");
}
createRoot(root).render(
  <StrictMode>
    <Suspense fallback={null}>
      <Page />
    </Suspense>
  </StrictMode>,
);
