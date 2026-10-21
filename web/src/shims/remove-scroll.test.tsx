import { render } from "@testing-library/react";
import { RemoveScroll } from "./remove-scroll";

describe("RemoveScroll (ADR-0010)", () => {
  it("ставит и снимает data-scroll-locked на body", () => {
    const { unmount } = render(<RemoveScroll>содержимое</RemoveScroll>);
    expect(document.body).toHaveAttribute("data-scroll-locked", "1");
    unmount();
    expect(document.body).not.toHaveAttribute("data-scroll-locked");
  });

  it("считает вложенные блокировки", () => {
    const a = render(<RemoveScroll>a</RemoveScroll>);
    const b = render(<RemoveScroll>b</RemoveScroll>);
    expect(document.body).toHaveAttribute("data-scroll-locked", "2");
    b.unmount();
    expect(document.body).toHaveAttribute("data-scroll-locked", "1");
    a.unmount();
    expect(document.body).not.toHaveAttribute("data-scroll-locked");
  });

  it("не блокирует при enabled=false и не передаёт параметры оригинала в DOM", () => {
    const { container } = render(
      <RemoveScroll enabled={false} allowPinchZoom shards={[]} className="x">
        z
      </RemoveScroll>,
    );
    expect(document.body).not.toHaveAttribute("data-scroll-locked");
    expect(container.firstElementChild).toHaveClass("x");
    expect(container.firstElementChild).not.toHaveAttribute("allowpinchzoom");
  });
});
