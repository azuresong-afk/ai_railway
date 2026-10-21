import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

// Макет примитивов Radix UI для проверки CSP (задача 2.22); в корень консоли не входит.
const RadixMockup = lazy(() => import("./dev/RadixMockup").then((m) => ({ default: m.RadixMockup })));

const root = document.getElementById("root");
if (!root) {
  throw new Error("Нет элемента #root");
}
createRoot(root).render(
  <StrictMode>
    {location.hash === "#/dev/radix" ? (
      <Suspense fallback={null}>
        <RadixMockup />
      </Suspense>
    ) : (
      <App />
    )}
  </StrictMode>,
);
