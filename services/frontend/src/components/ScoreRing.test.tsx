import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScoreRing } from "./ScoreRing";

describe("ScoreRing", () => {
  it("labels the score for assistive tech", () => {
    render(<ScoreRing score={72} />);
    expect(screen.getByRole("img", { name: "Security score 72 out of 100" })).toBeInTheDocument();
  });

  it("clamps out-of-range scores", () => {
    render(<ScoreRing score={140} />);
    expect(screen.getByRole("img", { name: "Security score 100 out of 100" })).toBeInTheDocument();
  });

  it.each([
    [90, "stroke-success-fg"],
    [60, "stroke-warning-fg"],
    [20, "stroke-danger-fg"]
  ])("colours %i with %s", (score, cls) => {
    const { container } = render(<ScoreRing score={score} />);
    expect(container.querySelector(`circle.${cls}`)).not.toBeNull();
  });

  it("renders an empty ring when there is no score", () => {
    const { container } = render(<ScoreRing score={null} />);
    expect(screen.getByRole("img", { name: "Security score unavailable" })).toBeInTheDocument();
    expect(container.querySelectorAll("circle")).toHaveLength(1);
  });
});
