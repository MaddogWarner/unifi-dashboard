import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders the title as the page heading with description and actions", () => {
    render(<PageHeader title="Firewall" description="Zone policies" actions={<button>Refresh</button>} />);
    expect(screen.getByRole("heading", { level: 1, name: "Firewall" })).toBeInTheDocument();
    expect(screen.getByText("Zone policies")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("omits the description when none is given", () => {
    const { container } = render(<PageHeader title="Scanner" />);
    expect(container.querySelector("p")).toBeNull();
  });
});
