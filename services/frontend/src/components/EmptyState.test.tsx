import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Badge } from "./Badge";
import { EmptyState } from "./EmptyState";
import { Skeleton } from "./Skeleton";

describe("primitives", () => {
  it("EmptyState shows title and detail", () => {
    render(<EmptyState title="Nothing here" detail="Check back later" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
    expect(screen.getByText("Check back later")).toBeInTheDocument();
  });

  it("Badge renders its children with the tone", () => {
    render(<Badge tone="warning">Warn</Badge>);
    expect(screen.getByText("Warn").className).toContain("warning");
  });

  it("Skeleton is hidden from assistive tech", () => {
    const { container } = render(<Skeleton className="h-4" />);
    expect(container.firstElementChild).toHaveAttribute("aria-hidden", "true");
  });
});
