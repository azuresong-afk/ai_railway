import { render, screen } from "@testing-library/react";
import { App } from "./App";

describe("App", () => {
  it("показывает заголовок", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "AISec" })).toBeInTheDocument();
  });
});
