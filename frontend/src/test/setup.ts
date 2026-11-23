import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import { useStore } from "../lib/store";

// Recharts y algunos layouts usan ResizeObserver, que jsdom no trae.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
(globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver ??= ResizeObserverStub;

afterEach(() => {
  cleanup();
  useStore.setState({ dialog: null, drawer: null, lang: "es" });
});
