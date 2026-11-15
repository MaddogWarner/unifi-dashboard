import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CopyButton } from "./CopyButton";

afterEach(() => {
  Reflect.deleteProperty(navigator, "clipboard");
});

describe("CopyButton", () => {
  it("copies the value and confirms", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(<CopyButton value="1.2.3.4" label="Copy source IP" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy source IP" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Copied"));
    expect(writeText).toHaveBeenCalledWith("1.2.3.4");
  });

  it("reports failure when the clipboard is unavailable", async () => {
    render(<CopyButton value="x" label="Copy" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Copy failed"));
  });

  it("does not trigger parent click handlers", () => {
    const parent = vi.fn();
    render(
      <div onClick={parent}>
        <CopyButton value="x" label="Copy" />
      </div>
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(parent).not.toHaveBeenCalled();
  });
});
