type CommandRow = {
  command: string;
  description: string;
};

const COMMAND_ROW_RE = /^(\/\S+)\s*(?:→|->|:)\s*(.+)$/;

function normalizeCommandText(content: string): string {
  return content
    .replaceAll("â€”", "—")
    .replaceAll("â†’", "→")
    .replaceAll("â€¦", "...")
    .replaceAll("â€™", "'");
}

function splitParagraphs(lines: string[]): string[] {
  const paragraphs: string[] = [];
  let current: string[] = [];

  for (const line of lines) {
    if (!line.trim()) {
      if (current.length) {
        paragraphs.push(current.join("\n"));
        current = [];
      }
      continue;
    }
    current.push(line);
  }

  if (current.length) {
    paragraphs.push(current.join("\n"));
  }

  return paragraphs;
}

export function isCommandHelpMessage(content: string): boolean {
  const normalized = normalizeCommandText(content);
  return (
    normalized.includes("Available commands:") &&
    normalized.split(/\r?\n/).some((line) => COMMAND_ROW_RE.test(line.trim()))
  );
}

export default function CommandHelpMessage({ content }: { content: string }) {
  const normalized = normalizeCommandText(content);
  const lines = normalized.split(/\r?\n/);
  const commandRows: CommandRow[] = [];
  const beforeCommands: string[] = [];
  const afterCommands: string[] = [];

  let inCommands = false;

  for (const line of lines) {
    const trimmed = line.trim();
    const match = trimmed.match(COMMAND_ROW_RE);

    if (match) {
      inCommands = true;
      commandRows.push({ command: match[1], description: match[2] });
      continue;
    }

    if (!inCommands) {
      beforeCommands.push(line);
    } else {
      afterCommands.push(line);
    }
  }

  const beforeParagraphs = splitParagraphs(beforeCommands);
  const afterParagraphs = splitParagraphs(afterCommands);

  return (
    <div className="space-y-4 font-mono text-[13px] leading-6">
      {beforeParagraphs.map((paragraph, index) => (
        <div key={`before-${index}`} className="whitespace-pre-wrap">
          {paragraph}
        </div>
      ))}

      {commandRows.length ? (
        <div className="grid grid-cols-[max-content_max-content_minmax(0,1fr)] gap-x-3 gap-y-1">
          {commandRows.map((row) => (
            <div
              key={`${row.command}-${row.description}`}
              className="contents"
            >
              <div className="whitespace-nowrap">{row.command}</div>
              <div aria-hidden="true">→</div>
              <div>{row.description}</div>
            </div>
          ))}
        </div>
      ) : null}

      {afterParagraphs.map((paragraph, index) => (
        <div key={`after-${index}`} className="whitespace-pre-wrap">
          {paragraph}
        </div>
      ))}
    </div>
  );
}
