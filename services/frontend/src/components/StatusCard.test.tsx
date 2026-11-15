import { render, screen } from "@testing-library/react";
import { Shield } from "lucide-react";
import { describe, expect, it } from "vitest";

import { StatusCard } from "./StatusCard";

describe("StatusCard", () => {
  it("renders the label and value", () => {
    render(<StatusCard icon={Shield} label="Score" value={72} />);
    expect(screen.getByText("Score")).toBeInTheDocument();
    expect(screen.getByText("72")).toBeInTheDocument();
  });

  it("applies the tone to the icon chip", () => {
    const { container } = render(<StatusCard icon={Shield} label="Score" value="Bad" tone="bad" />);
    expect(container.querySelector("svg")?.parentElement?.className).toContain("danger");
  });
});
