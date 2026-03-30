import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Send,
  Plus,
} from "lucide-react";

interface Section {
  id: string;
  title: string;
  body: string;
  bullets?: string[];
}

interface ScopeData {
  meta: {
    year: number;
    version: string;
    title: string;
    template_name?: string;
    created_at?: string;
    placeholders_retained?: boolean;
    source_file?: string;
    fallback_used?: boolean;
    missing_saved_file?: string | null;
    popup_message?: string | null;
  };
  sections: Section[];
}

type ChatMessage = { role: "user" | "assistant"; content: string };

type AgentCommand =
  | "help"
  | "commands"
  | "fill"
  | "exit"
  | "autofill"
  | "load"
  | "submit"
  | "reset"
  | "cancel"
  | "yes"
  | "no";

type LoadOption = { id: string; label: string };

interface AgentResponse {
  message: string;
  draft: ScopeData | null;
  next_question?: string | null;
  saved_version?: string | null;
  load_options?: LoadOption[] | null;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const YEAR = 2026;

function renderWithPlaceholders(text: string) {
  const parts = (text ?? "").split(/(\[[^\]]+\])/g);

  return parts.map((part, idx) => {
    const isPlaceholder = /^\[[^\]]+\]$/.test(part);
    if (!isPlaceholder) return <React.Fragment key={idx}>{part}</React.Fragment>;

    return (
      <span key={idx} className="font-semibold text-rose-300">
        {part}
      </span>
    );
  });
}

function stripSlash(cmd: string) {
  const t = cmd.trim();
  return t.startsWith("/") ? t.slice(1) : t;
}

function ShellCard({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={[
        "rounded-2xl border border-white/10 bg-white/5 shadow-xl ring-1 ring-white/10",
        className,
      ].join(" ")}
    >
      {children}
    </div>
  );
}

export default function ScopeContext() {
  const [data, setData] = useState<ScopeData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<number>(1);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "I’m in command mode.\n" +
        "Use: /help, /commands, /fill, /autofill, /load, /submit, /reset, /cancel\n" +
        "Confirmations: /yes, /no\n" +
        "Conversation mode: /exit\n\n" +
        "Tip: Type /commands to see the full list.",
    },
  ]);

  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [fillQuestion, setFillQuestion] = useState<string | null>(null);
  const [loadOptions, setLoadOptions] = useState<LoadOption[] | null>(null);

  const chatBottomRef = useRef<HTMLDivElement | null>(null);

  const NAV_ITEMS = [
    { step: 1, name: "Scope & Context", href: "#/scope" },
    { step: 2, name: "Asset Inventory & CIA", href: "#/assets" },
    { step: 3, name: "Threats & Vulnerabilities", href: "#/threats" },
    { step: 4, name: "Existing Controls & Posture", href: "#/controls" },
    { step: 5, name: "Risk Analysis", href: "#/" },
    { step: 6, name: "Risk Evaluation", href: "#/" },
    { step: 7, name: "Risk Treatment", href: "#/" },
    { step: 8, name: "Annex A & SoA", href: "#/" },
    { step: 9, name: "Action Plan / Implementation", href: "#/" },
    { step: 10, name: "Monitoring & Improvement", href: "#/" },
    { step: 11, name: "Final Deliverables", href: "#/" },
  ];

  const LEFT_MENU_ITEMS = [
    { step: 1, name: "Scope & Context", href: "#/scope" },
    { step: 2, name: "Asset Inventory & CIA", href: "#/assets" },
    { step: 3, name: "Threats & Vulnerabilities", href: "#/threats" },
    { step: 4, name: "Existing Controls & Posture", href: "#/controls" },
    { step: 5, name: "Risk Analysis", href: "#/risk-analysis" },
    { step: 6, name: "Risk Evaluation/Treatment", href: "#/risk-evaluation-treatment" },
    { step: 7, name: "Annex A & SoA", href: "#/annex-a-soa" },
    { step: 8, name: "Action Plan / Implementation", href: "#/" },
    { step: 9, name: "Monitoring & Improvement", href: "#/" },
    { step: 10, name: "Final Deliverables", href: "#/" },
  ];
    
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending, loadOptions]);

  useEffect(() => {
    const syncFromHash = () => {
      const h = (window.location.hash || "").toLowerCase();

      if (h.startsWith("#/scope")) setSelectedStep(1);
      else if (h.startsWith("#/assets")) setSelectedStep(2);
      else if (h.startsWith("#/threats")) setSelectedStep(3);
      else setSelectedStep(1);
    };

    syncFromHash();
    window.addEventListener("hashchange", syncFromHash);
    return () => window.removeEventListener("hashchange", syncFromHash);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        setErr(null);
        const res = await fetch(`${API_BASE}/api/scope/context?year=${YEAR}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as ScopeData;
        setData(json);
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
        setData(null);
      }
    })();
  }, []);

  useEffect(() => {
    if (!data?.meta?.popup_message) return;
    window.alert(data.meta.popup_message);
  }, [data]);

  const title = useMemo(() => data?.meta?.title ?? "Scope & Context", [data]);

  async function callAgent(commandRaw: string, answer?: string): Promise<AgentResponse> {
    const command = stripSlash(commandRaw).toLowerCase() as AgentCommand;
    const url = `${API_BASE}/api/scope/agent`;

    const payload = {
      year: YEAR,
      command,
      draft: data ?? null,
      answer: answer ?? null,
    };

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} @ ${url}${txt ? ` | ${txt}` : ""}`);
    }

    return (await res.json()) as AgentResponse;
  }

  function normalizeCommand(text: string): AgentCommand | null {
    const t = stripSlash(text).trim().toLowerCase();

    const map: Record<string, AgentCommand> = {
      help: "help",
      commands: "commands",
      fill: "fill",
      autofill: "autofill",
      load: "load",
      submit: "submit",
      reset: "reset",
      cancel: "cancel",
      yes: "yes",
      no: "no",
      exit: "exit",
    };

    return map[t] ?? null;
  }

  async function handleLoadSelection(opt: LoadOption) {
    if (sending) return;
    setSending(true);

    try {
      setMessages((prev) => [...prev, { role: "user", content: opt.label }]);

      let resp: AgentResponse;

      if (fillQuestion === "__FILL__") {
        resp = await callAgent("fill", opt.id);
      } else if (fillQuestion === "__LOAD__") {
        resp = await callAgent("autofill", opt.id);
      } else {
        resp = await callAgent("load", opt.id);
      }

      if (resp.draft) setData(resp.draft);

      setMessages((prev) => [...prev, { role: "assistant", content: resp.message }]);
      setLoadOptions(resp.load_options ?? null);
      setFillQuestion(resp.next_question ?? null);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `⚠️ ${e instanceof Error ? e.message : String(e)}` },
      ]);
    } finally {
      setSending(false);
    }
  }

  async function onSend() {
    const raw = input;
    const text = raw.trim();
    if (!text || sending) return;

    setMessages((prev) => [...prev, { role: "user", content: text }]);
    setInput("");
    setSending(true);

    try {
      const lower = text.toLowerCase();
      const loadArg = lower.startsWith("/load ") ? text.slice(6).trim() : null;

      if (fillQuestion) {
        const maybeCmd = normalizeCommand(text);

        if (maybeCmd) {
          const resp = await callAgent(maybeCmd);
          if (resp.draft) setData(resp.draft);

          setMessages((prev) => [...prev, { role: "assistant", content: resp.message }]);
          setLoadOptions(resp.load_options ?? null);
          setFillQuestion(resp.next_question ?? null);
          return;
        }

        const resp = await callAgent("fill", text);
        if (resp.draft) setData(resp.draft);

        setMessages((prev) => [...prev, { role: "assistant", content: resp.message }]);
        setLoadOptions(resp.load_options ?? null);
        setFillQuestion(resp.next_question ?? null);
        return;
      }

      let cmd = normalizeCommand(text);
      let answer: string | undefined = undefined;

      if (!cmd && loadArg !== null) {
        cmd = "load";
        answer = loadArg;
      }

      if (!cmd) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content:
              "I’m in command mode.\n\n" +
              "Type /commands to see the full list.\n" +
              "Tip: use /fill to start conversation mode.",
          },
        ]);
        return;
      }

      const resp = await callAgent(cmd, answer);
      if (resp.draft) setData(resp.draft);

      setMessages((prev) => [...prev, { role: "assistant", content: resp.message }]);
      setLoadOptions(resp.load_options ?? null);
      setFillQuestion(resp.next_question ?? null);
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `⚠️ ${e instanceof Error ? e.message : String(e)}` },
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="h-screen overflow-hidden bg-[#070A12] text-slate-50">
      {/* Mobile / small screens */}
      <div className="xl:hidden">
        <aside className="border-b border-white/10 bg-[#060815]">
          <div className="px-5 py-5">
            <div className="flex items-center gap-3">
              <div className="grid h-10 w-10 place-items-center rounded-xl bg-sky-500/15 ring-1 ring-sky-500/25">
                <ShieldCheck className="h-5 w-5 text-sky-200" />
              </div>
              <div>
                <div className="text-lg font-semibold tracking-tight">ISO 27001</div>
                <div className="text-sm text-slate-400">Audit Lifecycle</div>
              </div>
            </div>
          </div>

          <nav className="grid grid-cols-1 gap-1 px-3 pb-3 sm:grid-cols-2">
            {LEFT_MENU_ITEMS.map((item) => {
              const active = selectedStep === item.step;
              return (
                <button
                  key={item.step}
                  onClick={() => {
                    setSelectedStep(item.step);
                    window.location.hash = item.href;
                  }}
                  className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm ${
                    active ? "bg-white/5 ring-1 ring-white/10" : "hover:bg-white/5"
                  }`}
                >
                  <span
                    className={`grid h-7 w-7 place-items-center rounded-lg text-xs ${
                      active
                        ? "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25"
                        : "bg-white/5 text-slate-300 ring-1 ring-white/10"
                    }`}
                  >
                    {item.step}
                  </span>
                  <span className={`${active ? "text-slate-50" : "text-slate-200"}`}>
                    {item.name}
                  </span>
                </button>
              );
            })}
          </nav>

          <div className="px-4 pb-4">
            <button
              onClick={() => (window.location.hash = "#/dashboard")}
              className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
            >
              Dashboard
            </button>
          </div>
        </aside>

        <main className="px-4 py-4">
          <header className="mb-4">
            <div className="rounded-2xl border border-white/10 bg-[#070A12] py-4 text-center ring-1 ring-white/10">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                Scope &amp; Context
              </h1>
            </div>
          </header>

          <div className="space-y-4">
            <ShellCard className="p-4">
              <div className="flex flex-col gap-3">
                <div className="text-lg text-slate-300">Document:</div>

                <div className="flex flex-col gap-3">
                  <div className="relative">
                    <select
                      value={title}
                      disabled
                      aria-label="Scope document"
                      className="w-full cursor-not-allowed appearance-none rounded-xl border border-white/10 bg-white/5 px-4 py-2 pr-10 text-sm text-slate-100 opacity-90 ring-1 ring-white/10"
                    >
                      <option value={title}>{title}</option>
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-sm text-slate-300">
                    <span>Year: {data?.meta?.year ?? YEAR}</span>
                    <span>•</span>
                    <span>Version: {data?.meta?.version ?? "NA"}</span>
                  </div>
                </div>
              </div>
            </ShellCard>

            <div className="flex justify-end">
              <button className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600">
                <Plus className="h-4 w-4" />
                New Scope Draft
              </button>
            </div>

            <ShellCard className="flex min-h-[360px] flex-col p-5">
              <div className="shrink-0 text-lg font-semibold">{renderWithPlaceholders(title)}</div>

              <div className="mt-2 text-sm text-slate-400">
                Year: <span className="text-slate-200">{data?.meta?.year ?? YEAR}</span> • Version:{" "}
                <span className="text-slate-200">{data?.meta?.version ?? "NA"}</span>
              </div>

              <div className="mt-4 min-h-0 flex-1 overflow-auto rounded-xl ring-1 ring-white/10 p-4">
                {err ? (
                  <div className="rounded-xl border border-rose-500/20 bg-rose-500/15 p-5 ring-1 ring-rose-500/25">
                    <div className="text-sm text-rose-200">
                      Error loading Scope &amp; Context: {err}
                    </div>
                  </div>
                ) : !data ? (
                  <div className="rounded-xl border border-white/10 bg-white/5 p-6 ring-1 ring-white/10">
                    <div className="text-sm text-slate-300">Loading Scope &amp; Context…</div>
                  </div>
                ) : (
                  <div className="space-y-8">
                    {data.sections.map((section) => (
                      <article key={section.id} className="space-y-3">
                        <h3 className="text-lg font-semibold text-slate-100 md:text-xl">
                          {renderWithPlaceholders(section.title)}
                        </h3>

                        <p className="text-sm leading-relaxed text-slate-300 md:text-base">
                          {renderWithPlaceholders(section.body)}
                        </p>

                        {section.bullets && section.bullets.length > 0 ? (
                          <ul className="list-disc space-y-1 pl-6 text-sm text-slate-300 md:text-base">
                            {section.bullets.map((bullet, idx) => (
                              <li key={idx}>{renderWithPlaceholders(bullet)}</li>
                            ))}
                          </ul>
                        ) : null}
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </ShellCard>

            <ShellCard className="flex min-h-[520px] flex-col overflow-hidden">
              <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-5 py-4">
                <div className="text-lg font-semibold">Assistant</div>
                <div className="text-sm text-slate-400">
                  {sending
                    ? "Working…"
                    : loadOptions && fillQuestion === "__LOAD__"
                    ? "Load menu"
                    : fillQuestion
                    ? "Conversation mode"
                    : "Command mode"}
                </div>
              </div>

              <div className="flex min-h-0 flex-1 flex-col px-5 py-4">
                <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-[#060815] p-4 ring-1 ring-white/10">
                  <div className="space-y-3">
                    {messages.map((m, idx) => {
                      const isUser = m.role === "user";
                      return (
                        <div key={idx} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                          <div
                            className={`max-w-[90%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm ring-1 ${
                              isUser
                                ? "bg-indigo-600/30 text-slate-50 ring-indigo-500/30"
                                : "bg-white/5 text-slate-200 ring-white/10"
                            }`}
                          >
                            {m.content}
                          </div>
                        </div>
                      );
                    })}

                    {sending ? (
                      <div className="flex justify-start">
                        <div className="max-w-[90%] rounded-2xl bg-white/5 px-4 py-3 text-sm text-slate-200 ring-1 ring-white/10">
                          Thinking…
                        </div>
                      </div>
                    ) : null}

                    {loadOptions && loadOptions.length > 0 ? (
                      <div className="space-y-2 pt-1">
                        {loadOptions.map((opt) => (
                          <button
                            key={opt.id}
                            onClick={() => handleLoadSelection(opt)}
                            disabled={sending}
                            className="w-full rounded-xl border border-indigo-500/20 bg-indigo-600/15 px-4 py-3 text-left text-sm text-slate-100 ring-1 ring-indigo-500/20 hover:bg-indigo-600/25 disabled:opacity-50"
                          >
                            {opt.label}
                          </button>
                        ))}
                      </div>
                    ) : null}

                    <div ref={chatBottomRef} />
                  </div>
                </div>

                <div className="mt-4 flex shrink-0 items-center gap-2">
                  <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void onSend();
                    }}
                    placeholder={
                      fillQuestion
                        ? loadOptions && loadOptions.length > 0
                          ? "Choose an option or type your answer..."
                          : "Type your answer..."
                        : "Type a command (e.g., /help)..."
                    }
                    className="flex-1 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 ring-1 ring-white/10"
                    disabled={sending}
                  />
                  <button
                    onClick={() => void onSend()}
                    disabled={sending || !input.trim()}
                    className="inline-flex items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-3 text-sm font-semibold text-white hover:bg-indigo-600 disabled:opacity-60"
                  >
                    <Send className="h-4 w-4" />
                    Send
                  </button>
                </div>

                <div className="mt-3 shrink-0 text-xs text-slate-500">
                  Command mode: /help /commands /fill /autofill /load /submit /reset /cancel
                  <br />
                  Conversation mode: /exit
                </div>
              </div>
            </ShellCard>
          </div>
        </main>
      </div>

      {/* Desktop / large screens */}
      <div className="hidden xl:grid xl:h-screen xl:overflow-hidden xl:grid-cols-[280px_minmax(24px,4vw)_minmax(0,1.66fr)_minmax(380px,1fr)] xl:grid-rows-[89px_95px_minmax(0,1fr)]">
        {/* Section 1 */}
        <aside className="col-[1] row-[1/4] h-full overflow-hidden border-r border-white/10 bg-[#060815]">
          <div className="flex h-full min-h-0 flex-col">
            <div className="px-6 py-6">
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-xl bg-sky-500/15 ring-1 ring-sky-500/25">
                  <ShieldCheck className="h-5 w-5 text-sky-200" />
                </div>
                <div>
                  <div className="text-lg font-semibold tracking-tight">ISO 27001</div>
                  <div className="text-sm text-slate-400">Audit Lifecycle</div>
                </div>
              </div>
            </div>

            <nav className="min-h-0 flex-1 overflow-y-auto px-3">
              {LEFT_MENU_ITEMS.map((item) => {
                const active = selectedStep === item.step;
                return (
                  <button
                    key={item.step}
                    onClick={() => {
                      setSelectedStep(item.step);
                      window.location.hash = item.href;
                    }}
                    className={`mb-1 flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm ${
                      active ? "bg-white/5 ring-1 ring-white/10" : "hover:bg-white/5"
                    }`}
                  >
                    <span
                      className={`grid h-7 w-7 place-items-center rounded-lg text-xs ${
                        active
                          ? "bg-sky-500/15 text-sky-200 ring-1 ring-sky-500/25"
                          : "bg-white/5 text-slate-300 ring-1 ring-white/10"
                      }`}
                    >
                      {item.step}
                    </span>
                    <span className={`${active ? "text-slate-50" : "text-slate-200"}`}>
                      {item.name}
                    </span>
                  </button>
                );
              })}
            </nav>

            <div className="p-4">
              <button
                onClick={() => (window.location.hash = "#/dashboard")}
                className="w-full rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600"
              >
                Dashboard
              </button>
            </div>
          </div>
        </aside>

        {/* Section 2 */}
        <div className="col-[2] row-[1/4] border-r border-white/10 bg-[#070A12]" />

        {/* Section 3 */}
        <header className="col-[3/5] row-[1] h-full overflow-hidden border-b border-white/10 bg-[#070A12]">
          <div className="flex h-full items-center justify-center px-6">
            <h1 className="text-center text-3xl font-bold tracking-tight text-slate-100 md:text-4xl">
              Scope &amp; Context
            </h1>
          </div>
        </header>

        {/* Section 4 */}
        <div className="col-[3] row-[2] h-full overflow-hidden p-3 pr-2">
          <ShellCard className="flex min-h-[71px] items-center px-4">
            <div className="flex w-full flex-wrap items-center justify-between gap-4">
              <div className="flex min-w-0 flex-wrap items-center gap-3">
                <div className="text-xl text-slate-300">Document:</div>

                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <div className="relative min-w-[280px] max-w-[480px] flex-1">
                    <select
                      value={title}
                      disabled
                      aria-label="Scope document"
                      className="w-full cursor-not-allowed appearance-none rounded-xl border border-white/10 bg-white/5 px-4 py-2 pr-10 text-sm text-slate-100 opacity-90 ring-1 ring-white/10"
                    >
                      <option value={title}>{title}</option>
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  </div>

                  <span className="text-sm text-slate-300">
                    Year: {data?.meta?.year ?? YEAR} - Version: {data?.meta?.version ?? "NA"}
                  </span>
                </div>
              </div>
            </div>
          </ShellCard>
        </div>

        {/* Section 5 */}
        <div className="col-[4] row-[2] h-full overflow-hidden p-3 pl-2">
          <div className="flex min-h-[71px] items-center justify-end">
            <button className="inline-flex h-fit items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-600">
              <Plus className="h-4 w-4" />
              New Scope Draft
            </button>
          </div>
        </div>

        {/* Section 6 */}
        <div className="col-[3] row-[3] min-h-0 p-3 pr-2">
          <ShellCard className="flex h-full min-h-0 flex-col p-5">
            <div className="shrink-0 text-lg font-semibold">{renderWithPlaceholders(title)}</div>

            <div className="mt-2 text-sm text-slate-400">
              Year: <span className="text-slate-200">{data?.meta?.year ?? YEAR}</span> • Version:{" "}
              <span className="text-slate-200">{data?.meta?.version ?? "NA"}</span>
            </div>

            <div className="mt-4 min-h-0 flex-1 overflow-auto rounded-xl ring-1 ring-white/10 p-4">
              {err ? (
                <div className="rounded-2xl border border-rose-500/20 bg-rose-500/15 p-5 ring-1 ring-rose-500/25">
                  <div className="text-sm text-rose-200">
                    Error loading Scope &amp; Context: {err}
                  </div>
                </div>
              ) : !data ? (
                <div className="rounded-2xl border border-white/10 bg-white/5 p-6 ring-1 ring-white/10">
                  <div className="text-sm text-slate-300">Loading Scope &amp; Context…</div>
                </div>
              ) : (
                <div className="space-y-8">
                  {data.sections.map((section) => (
                    <article key={section.id} className="space-y-3">
                      <h3 className="text-lg font-semibold text-slate-100 md:text-xl">
                        {renderWithPlaceholders(section.title)}
                      </h3>

                      <p className="text-sm leading-relaxed text-slate-300 md:text-base">
                        {renderWithPlaceholders(section.body)}
                      </p>

                      {section.bullets && section.bullets.length > 0 ? (
                        <ul className="list-disc pl-6 text-sm text-slate-300 space-y-1 md:text-base">
                          {section.bullets.map((bullet, idx) => (
                            <li key={idx}>{renderWithPlaceholders(bullet)}</li>
                          ))}
                        </ul>
                      ) : null}
                    </article>
                  ))}
                </div>
              )}
            </div>
          </ShellCard>
        </div>

        {/* Section 7 */}
        <div className="col-[4] row-[3] min-h-0 p-3 pl-2">
          <ShellCard className="flex h-full min-h-0 flex-col overflow-hidden">
            <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-5 py-4">
              <div className="text-lg font-semibold">Assistant</div>
              <div className="text-sm text-slate-400">
                {sending
                  ? "Working…"
                  : loadOptions && fillQuestion === "__LOAD__"
                  ? "Load menu"
                  : fillQuestion
                  ? "Conversation mode"
                  : "Command mode"}
              </div>
            </div>

            <div className="flex min-h-0 flex-1 flex-col px-5 py-4">
              <div className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-white/10 bg-[#060815] p-4 ring-1 ring-white/10">
                <div className="space-y-3">
                  {messages.map((m, idx) => {
                    const isUser = m.role === "user";
                    return (
                      <div key={idx} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                        <div
                          className={`max-w-[90%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm ring-1 ${
                            isUser
                              ? "bg-indigo-600/30 text-slate-50 ring-indigo-500/30"
                              : "bg-white/5 text-slate-200 ring-white/10"
                          }`}
                        >
                          {m.content}
                        </div>
                      </div>
                    );
                  })}

                  {sending ? (
                    <div className="flex justify-start">
                      <div className="max-w-[90%] rounded-2xl bg-white/5 px-4 py-3 text-sm text-slate-200 ring-1 ring-white/10">
                        Thinking…
                      </div>
                    </div>
                  ) : null}

                  {loadOptions && loadOptions.length > 0 ? (
                    <div className="space-y-2 pt-1">
                      {loadOptions.map((opt) => (
                        <button
                          key={opt.id}
                          onClick={() => handleLoadSelection(opt)}
                          disabled={sending}
                          className="w-full rounded-xl border border-indigo-500/20 bg-indigo-600/15 px-4 py-3 text-left text-sm text-slate-100 ring-1 ring-indigo-500/20 hover:bg-indigo-600/25 disabled:opacity-50"
                        >
                          {opt.label}
                        </button>
                      ))}
                    </div>
                  ) : null}

                  <div ref={chatBottomRef} />
                </div>
              </div>

              <div className="mt-4 flex shrink-0 items-center gap-2">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void onSend();
                  }}
                  placeholder={
                    fillQuestion
                      ? loadOptions && loadOptions.length > 0
                        ? "Choose an option or type your answer..."
                        : "Type your answer..."
                      : "Type a command (e.g., /help)..."
                  }
                  className="flex-1 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 ring-1 ring-white/10"
                  disabled={sending}
                />
                <button
                  onClick={() => void onSend()}
                  disabled={sending || !input.trim()}
                  className="inline-flex items-center gap-2 rounded-xl bg-indigo-600/90 px-4 py-3 text-sm font-semibold text-white hover:bg-indigo-600 disabled:opacity-60"
                >
                  <Send className="h-4 w-4" />
                  Send
                </button>
              </div>

              <div className="mt-3 shrink-0 text-xs text-slate-500">
                Command mode: /help /commands /fill /autofill /load /submit /reset /cancel
                <br />
                Conversation mode: /exit
              </div>
            </div>
          </ShellCard>
        </div>
      </div>
    </div>
  );
}