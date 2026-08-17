export type StepStatus = "Not Started" | "In Progress" | "Completed";

export function normalizeStepStatus(status?: string | null): StepStatus {
  if (status === "Completed") return "Completed";
  if (status === "In Progress") return "In Progress";
  return "Not Started";
}

function badgeClasses(status: StepStatus): string {
  if (status === "Completed") {
    return "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25";
  }

  if (status === "In Progress") {
    return "bg-orange-500/15 text-orange-200 ring-1 ring-orange-500/25";
  }

  return "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/25";
}

function dotClasses(status: StepStatus): string {
  if (status === "Completed") return "bg-emerald-400";
  if (status === "In Progress") return "bg-orange-400";
  return "bg-yellow-400";
}

export default function StepStatusBadge({
  status,
  className = "",
}: {
  status?: string | null;
  className?: string;
}) {
  const normalized = normalizeStepStatus(status);

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs ${badgeClasses(
        normalized
      )} ${className}`.trim()}
    >
      <span className={`inline-block h-2.5 w-2.5 rounded-full ${dotClasses(normalized)}`} />
      {normalized}
    </span>
  );
}
