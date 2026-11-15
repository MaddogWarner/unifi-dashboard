import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FilterChips } from "./FilterChips";
import { IpCell } from "./IpCell";

describe("FilterChips", () => {
  it("renders nothing without active filters", () => {
    const { container } = render(<FilterChips active={[]} onRemove={() => {}} onClear={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("removes a single filter and clears all", () => {
    const onRemove = vi.fn();
    const onClear = vi.fn();
    render(
      <FilterChips active={[{ key: "src_ip", value: "1.2.3.4" }]} onRemove={onRemove} onClear={onClear} />
    );
    fireEvent.click(screen.getByRole("button", { name: "Remove filter src_ip 1.2.3.4" }));
    expect(onRemove).toHaveBeenCalledWith("src_ip");
    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));
    expect(onClear).toHaveBeenCalled();
  });
});

describe("IpCell", () => {
  it("applies the IP as a filter and does not bubble the click", () => {
    const onFilter = vi.fn();
    const parent = vi.fn();
    render(
      <div onClick={parent}>
        <IpCell ip="10.0.0.5" port={443} role="source" onFilter={onFilter} />
      </div>
    );
    fireEvent.click(screen.getByRole("button", { name: "10.0.0.5" }));
    expect(onFilter).toHaveBeenCalledWith("10.0.0.5");
    expect(parent).not.toHaveBeenCalled();
    expect(screen.getByText(":443")).toBeInTheDocument();
  });

  it("shows Unknown when there is no IP", () => {
    render(<IpCell ip={null} port={null} role="destination" onFilter={() => {}} />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});
