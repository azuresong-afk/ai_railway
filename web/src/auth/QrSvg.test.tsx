import { render } from "@testing-library/react";
import { QrSvg } from "./QrSvg";

describe("QrSvg", () => {
  it("рисует модули как контуры с белой зоной и без style", () => {
    const { container } = render(<QrSvg rows={["101", "010"]} label="код" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("viewBox")).toBe("0 0 11 11");
    expect(svg.getAttribute("aria-label")).toBe("код");
    expect(container.querySelector("path")!.getAttribute("d")).toBe("M4 4h1v1h-1zM6 4h1v1h-1zM5 5h1v1h-1z");
    expect(container.querySelector("style")).toBeNull();
  });
});
