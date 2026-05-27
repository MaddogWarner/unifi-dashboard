from dataclasses import dataclass

from app.models.firewall import FirewallPolicy


@dataclass
class ConflictReport:
    policy_a_id: int
    policy_b_id: int
    conflict_type: str
    description: str


def detect_conflicts(policies: list[FirewallPolicy]) -> list[ConflictReport]:
    reports: list[ConflictReport] = []
    ordered = sorted(policies, key=lambda policy: policy.id)
    for index, first in enumerate(ordered):
        for second in ordered[index + 1 :]:
            if first.src_zone != second.src_zone or first.dst_zone != second.dst_zone:
                continue
            overlaps = (
                first.protocol is None
                or second.protocol is None
                or first.protocol == second.protocol
            )
            if not overlaps:
                continue
            if first.action != second.action:
                reports.append(
                    ConflictReport(
                        policy_a_id=first.id,
                        policy_b_id=second.id,
                        conflict_type="shadow",
                        description=(
                            f"'{first.name}' ({first.action}) shadows "
                            f"'{second.name}' ({second.action}) on "
                            f"{first.src_zone}->{first.dst_zone}"
                        ),
                    )
                )
            else:
                reports.append(
                    ConflictReport(
                        policy_a_id=first.id,
                        policy_b_id=second.id,
                        conflict_type="duplicate",
                        description=(
                            f"'{first.name}' and '{second.name}' are duplicates on "
                            f"{first.src_zone}->{first.dst_zone}"
                        ),
                    )
                )
    return reports
