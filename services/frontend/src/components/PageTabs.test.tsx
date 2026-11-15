import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PageTabs } from "./PageTabs";

const tabs = [
  { id: "a", label: "Alpha" },
  { id: "b", label: "Beta" }
];

describe("PageTabs", () => {
  it("marks only the active tab as selected", () => {
    render(<PageTabs tabs={tabs} active="b" onChange={() => {}} />);
    expect(screen.getByRole("tab", { name: "Beta" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Alpha" })).toHaveAttribute("aria-selected", "false");
  });

  it("reports the clicked tab id", () => {
    const onChange = vi.fn();
    render(<PageTabs tabs={tabs} active="a" onChange={onChange} />);
    fireEvent.click(screen.getByRole("tab", { name: "Beta" }));
    expect(onChange).toHaveBeenCalledWith("b");
  });
});
