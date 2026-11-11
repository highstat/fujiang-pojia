// dsh-prompt-custom (standalone port) — client half: the Custom Prompts settings section.
//
// 0.5.0 redesign (the user decided that cards are prompts): reworked interactions and visuals.
//
// 1. Interactions (shortcomings in 0.4.0): the card list, Use This Card action, and separate Save
//   button created four layers of state. Highlighting required exact text equality; Save wrote only
//   the body, not the card. Editing and saving left the card on its old text, appearing to lose edits.
//   Switching required reaching across half the screen for Use This Card and resolving editor changes.
//   The two most common actions (switch cards / save text) followed separate, mutually unaware paths.
//   This version makes cards the **only body selector**:
//   1. Cards are selectable chips: click to switch to the card body and apply immediately (one POST
//      when the editor is clean). Unsaved edits offer three explicit choices: save and switch,
//      save as a new card and switch, or discard and switch. Each explains its consequences,
//      eliminating intermediate states where a click appears to do nothing.
//   2. Save writes back to the **current card** (the source of the body), naming its destination
//      directly on the button (Save to Card A and Apply); unassigned text uses Save and Apply.
//      Cards are no longer one-time snapshots: edit, save, and card synchronization form a complete loop.
//   3. New Card saves the current editor contents and activates them; branching uses Save as Card
//      in the switch panel.
//   4. Rename / Delete are inline actions on the Currently Active row, targeting the current card,
//      rather than three buttons on every card.
//   5. Preview collapses to one row; expanded, it switches between Full Official Prompt and Effective
//      Prompt, taking space only when comparison is needed.
//
// 2. Visuals: core design-system primitives (Button / Switch / SegmentedControl / Input / Pill / Tag /
//   DisclosureRow + official icons), with --dsw-* color and radius variables, matching existing settings
//   pages such as Built-in Plugins instead of custom-drawn checkboxes / selects.
//
// 3. Host and protocol **remain unchanged** (lib/index.js, API_PROTO=3, and the
//   $DSH_HOME/prompt-custom.json format): UI-only redesign; existing configurations still work.
//   Until the host restarts (proto != 3), the entire cards section stays disabled with an explanation.
window.__ModuleLoader__.load({
  id: "@deepseek-ai/dsh-prompt-custom",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    const react = require("react");
    const { jsx, jsxs } = require("react/jsx-runtime");
    // Core design-system primitives, imported once at the top as in companion plugins such as dsh-wsl-settings.
    const {
      Button, Switch, SegmentedControl, SegmentedTabs, Input, Pill, Tag, DisclosureRow, Modal,
      IconPlusOutlineRegular, IconChevronDownOutlineRegular,
      IconSettingsOutlineRegular, IconCloseOutlineRegular, IconSkillOutlineRegular
    } = require("@deepseek-ai/dsh-client-ui-primitives");

    const CONFIG_URL = "/api/dsh-prompt-custom/config";
    const PREVIEW_URL = "/api/dsh-prompt-custom/preview";
    const TOGGLE_URL = "/api/dsh-prompt-custom/toggle";
    const SKILLS_URL = "/api/dsh-prompt-custom/skills";
    const KNOWLEDGE_URL = "/api/dsh-prompt-custom/knowledge";
    const FINDINGS_URL = "/api/dsh-prompt-custom/findings";
    const FINDINGS_MD_URL = "/api/dsh-prompt-custom/findings.md";
    const CAMPAIGNS_URL = "/api/dsh-prompt-custom/campaigns";
    const SESSIONS_URL = "/api/dsh-prompt-custom/sessions";
    // Must match the host API_PROTO. Change protocol numbers in **only two places**: host API_PROTO and EXPECT_PROTO here.
    // 3 (0.4.0): config added cards; 4 adds the prompt-free composer toggle route.
    const EXPECT_PROTO = 11;

    const L = {
      nav: "Custom Prompts",
      title: "Custom Prompts",
      sub: "Edit the system prompt injected into the core: append it to the default persona or replace the persona entirely. The toggle and injection mode take effect immediately; text changes apply the next time the model is assembled, without starting a new session.",
      enabled: "Enable custom prompts",
      enabledHint: "Turning this off restores the official default prompt immediately; no save is needed.",
      toggleLabel: "Fujiang Armor Breaker",
      toggleError: "Failed to read toggle state",
      toggleRetry: "Retry",
      toggleOn: "Active",
      toggleOff: "Inactive",
      toggleLoading: "Loading",
      knowledgeTitle: "Knowledge Base",
      knowledgeHint: "CVE / PoC content ships with the plugin (offline, with no downloads or network access). When enabled, the model can invoke these category skills directly from the skills catalog. Their bodies enter context only when invoked; otherwise each occupies just one description line in the catalog.",
      knowledgeTotal: (n, m) => m + " categories · " + n + " entries",
      knowledgeOn: "Injected: the model can invoke these categories directly from the skills catalog.",
      knowledgeOff: "Disabled: category skills are absent from the model catalog; the content remains in the plugin directory.",
      knowledgeEmpty: "No categories have loaded yet.",
      knowledgeRestart: "If you just updated the plugin, fully quit DSH and restart it.",
      knowledgeLoading: "Loading…",
      reportTitle: "Vulnerability Report",
      reportSub: "Vulnerabilities the AI finds in sessions appear here (critical / high / medium / low / informational). Filter by severity, change statuses, and export Markdown.",
      reportEmpty: "No entries yet. The AI writes findings automatically; you can also add one manually with the command below.",
      reportTotal: (n, open) => n + " entries total · " + open + " open",
      reportAll: "All",
      reportExport: "Export Markdown",
      reportClear: "Clear report",
      reportClearAsk: "Clear the entire vulnerability report? This takes effect immediately and cannot be undone.",
      reportHint: "How the AI writes findings (one command)",
      reportStatusOpen: "Open",
      reportStatusFixed: "Fixed",
      reportStatusAccepted: "Risk accepted",
      reportStatusFalse: "False positive",
      reportDelete: "Delete",
      reportVerify: "Verified",
      reportUnverified: "Unverified",
      reportLoading: "Loading…",
      reportSearchPlaceholder: "Search title / target / URL / CVE",
      reportNoMatch: "No matching entries.",
      reportUpdated: (t) => "Last updated " + t,
      reportSource: "Source",
      reportCvss: "CVSS",
      reportDetailDescription: "Description",
      reportDetailEvidence: "Evidence",
      reportDetailRemediation: "Remediation",
      reportDetailRefs: "References",
      reportAiHint: "AI write example (copy and use)",
      taskTitle: "Penetration Testing Workflow",
      taskNew: "New campaign",
      taskEmpty: "No campaigns yet. Only you can create one here: enter the target domain / network range before the AI can advance through Reconnaissance → Fingerprinting → Vulnerability Matching → Feasibility Validation → Exploitation → Lateral Movement → Reporting.",
      taskLoading: "Loading…",
      taskStage: "Stage",
      taskNext: "Next stage",
      taskDelete: "Delete campaign",
      taskDeleteAsk: "Delete this campaign? Its ledger will also be deleted; entries already written to the vulnerability report are unaffected.",
      taskAssets: "Assets",
      taskSteps: "Steps",
      taskScope: "Scope",
      taskSuggest: "Suggested next steps",
      taskNoAdvice: "Nothing in the ledger to advance yet: add assets first (host/port/fingerprint).",
      taskNamePlaceholder: "Campaign name, e.g. oa.example.com external assessment",
      taskPrev: "Previous stage",
      taskObjective: "Objective: ",
      taskDone: "Mark complete",
      taskDoneHint: "Click here once the objective is achieved to stop automatic continuation.",
      taskBind: "Bind",
      taskBindPick: "Bind to: ",
      taskKick: "Start AI",
      taskKicked: "Sent the start instruction to the AI; it will provide a plan first.",
      taskKickHint: "Tip: ",
      taskUnbind: "Unbind",
      taskBound: "Bound session: ",
      taskUnbound: "No conversation bound: click Bind Campaign in the campaign bar to the left of the conversation input to bind only the current conversation.",
      taskProgress: "Progress",
      taskScopePlaceholder: "Target scope: domains or IP ranges, comma-separated (optional; add later)",
      taskCreate: "Create",
      taskCancel: "Cancel",
      taskCreateHint: "Only you can create campaigns. Once created, the AI can add assets, record steps, and advance stages.",
      pluginSettings: "Fujiang Armor Breaker Settings",
      pluginFunctions: "Plugin Features",
      pluginSettingsHint: "Plugin settings",
      closeSettings: "Close Fujiang Armor Breaker settings",
      skillsTitle: "Skill Library",
      skillsEmpty: "No skills added yet",
      skillsEmptyHint: "Added skills appear here.",
      mode: "Injection mode",
      modeHint: "Append preserves the default persona; Replace overrides it. Switching takes effect immediately (different mount points require reinjection).",
      modeAppend: "Append to end",
      modeReplace: "Replace entirely",
      text: "Prompt content",
      textHint: "Injected as written; core variables such as {{model}} and {{cwd}} are supported.",
      savePlain: "Save and apply",
      saveTo: (name) => "Save to “" + name + "” and apply",
      revert: "Revert changes",
      saving: "Applying…",
      saved: "Saved and applied",
      savedToCard: (name) => "Saved to card “" + name + "” and applied.",
      loading: "Loading…",
      unavailable: "Settings unavailable (open in a browser on this machine)",
      dirtyTag: "Unsaved",
      previewTitle: "Preview",
      previewOfficial: "Full official prompt",
      previewEffective: "Effective prompt",
      previewHintOfficial: "The full official prompt without this plugin's custom section, for reference when writing replacement content.",
      previewHintEffective: "The complete text the model actually sees at this step, including the custom section.",
      previewReload: "Reload",
      previewing: "Loading…",
      previewNoAgent: "No active session: only the global view is available. After creating a session, Effective Prompt will be more accurate.",
      staleHost: "⚠ UI and host plugin versions differ: the page has refreshed (new UI), but the host process has not restarted (old plugin). **Fully quit** DeepSeek Harness, including remaining tray / Task Manager processes, then restart. Refreshing the page alone does not reload the host plugin. Until restarting, previews may fall back to old API text and prompt cards are unavailable.",
      unknownCfgKeys: (keys) => "⚠ This version does not recognize these configuration fields: " + keys + ". This usually means **another version** of the plugin wrote the file; this version may not have read your previous settings. Back up the configuration file before continuing.",
      previewError: "Failed to load preview",
      varWarn: (names) => "Warning: the core does not recognize these variables: " + names + ". Unknown variables cause errors in the core and fail every run. Correct their names or remove them.",
      varMalformed: (names) => "Warning: these references are malformed: " + names + ". Variable names must match [a-z][a-z0-9_]*.",
      storage: "Configuration file",
      stOff: "Disabled: using the official default prompt",
      stArmed: "Enabled: automatically injected into new sessions",
      stInjected: (n) => "Applied: currently injected into " + n + " sessions",
      stError: (m) => "Injection failed: " + m,
      cardsTitle: "Prompt Cards",
      cardsHint: "Click a card to switch and apply it. Use the button below to write text changes back to the current card.",
      cardsAdd: "New card",
      cardsEmpty: "No prompt cards yet. Save your edited prompt with New Card; then switch with a single click.",
      cardsVirtual: "Current text",
      cardsCurrent: (name, len) => "Currently active: card “" + name + "” · " + len + " characters",
      cardsCurrentCustom: (len) => "Current text: custom (not saved to a card) · " + len + " characters",
      cardsCurrentNone: "Current text is empty",
      cardsRename: "Rename",
      cardsRemove: "Delete",
      cardsRenameLabel: "New name",
      cardsNamePlaceholder: "Name the card (leave blank for an automatic name)",
      cardsRenameSave: "Save name",
      cardsCancel: "Cancel",
      cardsRemoveAsk: (name) => "Delete card “" + name + "”? This cannot be undone.",
      cardsRemoveConfirm: "Confirm deletion",
      cardsAddHint: "Saves the current editor contents, including unsaved changes, and makes them active.",
      cardsSave: "Save as card",
      cardsNoteAdded: (name) => "Saved as card “" + name + "” and applied.",
      cardsNoteUsed: (name) => "Switched to card “" + name + "” and applied.",
      cardsNoteSavedSwitched: (saved, used) => "Saved to card “" + saved + "” and switched to “" + used + "”.",
      cardsNoteForkedSwitched: (forked, used) => "Saved as new card “" + forked + "” and switched to “" + used + "”.",
      cardsNoteRemoved: (name) => "Card “" + name + "” deleted.",
      cardsNoteRenamed: (name) => "Card renamed to “" + name + "”.",
      cardsUseDirty: "The editor has unsaved changes. Resolve them before switching cards:",
      cardsSwitchSave: (name) => "Save to “" + name + "” and switch",
      cardsSwitchFork: "Save as card and switch",
      cardsSwitchDiscard: "Discard changes and switch",
      cardsLimit: "Card limit reached (maximum 50).",
      cardsStale: "The host plugin is still an older version, so prompt cards are unavailable. Fully quit DeepSeek Harness and restart it."
    };

    /** Turn armed / injected / lastError from /config into a readable status sentence. */
    function statusLine(st) {
      if (!st) return null;
      if (st.lastError) return { text: L.stError(st.lastError), tone: "error" };
      // Older hosts omit armed/injected, so status is unknown. Show nothing rather than
      // falsely reporting Disabled due to !undefined when mixing versions.
      if (st.armed === undefined && st.injected === undefined) return null;
      if (!st.armed) return { text: L.stOff, tone: "muted" };
      if (st.injected > 0) return { text: L.stInjected(st.injected), tone: "ok" };
      return { text: L.stArmed, tone: "muted" };
    }

    // Prompt card limit: must match host MAX_CARDS (the host truncates; prevent additions here first).
    const CARDS_MAX = 50;

    /** Card IDs are local and decoupled from the backend; their format matches the host CARD_ID regex. */
    function newCardId() {
      return "c" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    }

    /** Suggest a name: first line without heading markers, limited to 24 characters; fall back to a sequence number. */
    function suggestName(text, count) {
      const line = String(text || "")
        .split("\n")
        .map((s) => s.replace(/^#+\s*/, "").trim())
        .find((s) => s.length > 0) || "";
      return line ? line.slice(0, 24) : "Prompt card " + (count + 1);
    }

    function note(text, tone) {
      return jsx("div", {
        style: {
          fontSize: 12,
          lineHeight: "18px",
          color: tone === "error" ? "var(--dsw-alias-label-error)"
            : (tone === "warn" ? "var(--dsw-alias-state-warn-primary)" : undefined),
          opacity: tone === "muted" ? 0.75 : 1,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word"
        },
        children: text
      });
    }

    // Inline styles use core design-system color and radius variables (--dsw-*), matching settings such as Built-in Plugins.
    const S = {
      root: { display: "flex", flexDirection: "column", gap: 14, padding: 16, maxWidth: 720 },
      head: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" },
      h2: { margin: 0, fontSize: 16, fontWeight: 600, color: "var(--dsw-alias-label-primary)" },
      sub: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)" },
      hint: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)" },
      field: { display: "flex", flexDirection: "column", gap: 6 },
      fieldTitle: { fontSize: 13, fontWeight: 600, color: "var(--dsw-alias-label-primary)" },
      row: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" },
      panel: {
        display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
        padding: "8px 10px",
        border: "1px solid var(--dsw-alias-border-l3)",
        borderRadius: "var(--dsw-radius-md)",
        background: "var(--dsw-alias-bg-layer-3)"
      },
      warnPanel: {
        display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
        padding: "8px 10px",
        border: "1px solid var(--dsw-alias-state-warn-primary)",
        borderRadius: "var(--dsw-radius-md)",
        background: "var(--dsw-alias-bg-layer-3)"
      },
      textarea: {
        width: "100%", boxSizing: "border-box", padding: "8px 10px",
        fontFamily: "inherit", fontSize: 13, lineHeight: "20px",
        color: "var(--dsw-alias-label-primary)",
        background: "var(--dsw-alias-bg-layer-2)",
        border: "1px solid var(--dsw-alias-border-l2)",
        borderRadius: "var(--dsw-radius-md)",
        resize: "vertical", outline: "none"
      },
      mono: {
        width: "100%", boxSizing: "border-box", padding: "8px 10px",
        fontFamily: "monospace, inherit", fontSize: 12, lineHeight: "18px",
        color: "var(--dsw-alias-label-primary)",
        background: "var(--dsw-alias-bg-layer-2)",
        border: "1px solid var(--dsw-alias-border-l2)",
        borderRadius: "var(--dsw-radius-md)",
        resize: "vertical", outline: "none"
      }
    };

    const EMPTY = { enabled: false, mode: "append", text: "", cards: [] };

    function Card({ embedded = false, sessionId = "" } = {}) {
      const [cfg, setCfg] = react.useState(EMPTY);           // Editor state (text may be unsaved)
      const [savedCfg, setSavedCfg] = react.useState(EMPTY); // Server-saved configuration (card source of truth)
      const [state, setState] = react.useState("loading");
      const [busy, setBusy] = react.useState(false);
      const [notice, setNotice] = react.useState("");
      const [sessions, setSessions] = react.useState([]);
      const [pick, setPick] = react.useState("");
      const [cardNotice, setCardNotice] = react.useState("");
      const [vars, setVars] = react.useState({ unknown: [], malformed: [] });
      const [file, setFile] = react.useState("");
      const [st, setSt] = react.useState(null);
      // Fields may be missing when the page refreshes without a host restart (see L.staleHost).
      const [stale, setStale] = react.useState(false);
      // Configuration keys unknown to this version (schema evolution safeguard; see L.unknownCfgKeys).
      const [cfgKeys, setCfgKeys] = react.useState([]);
      // Preview starts collapsed and loads on expansion, rather than permanently occupying half the screen.
      const [previewOpen, setPreviewOpen] = react.useState(false);
      const [previewKind, setPreviewKind] = react.useState("official");
      const [preview, setPreview] = react.useState(null);    // { kind, text, error }
      const [previewBusy, setPreviewBusy] = react.useState(false);
      // Transient card UI state; savedCfg.cards alone is the source of truth, everything here is in-progress state.
      const [adding, setAdding] = react.useState(false);    // New Card panel expanded
      const [newName, setNewName] = react.useState("");
      const [pending, setPending] = react.useState(null);   // Awaiting confirmation: { kind: "use"|"remove"|"rename", id }
      const [renameText, setRenameText] = react.useState("");

      const applyStatus = (data) => {
        setSt({ armed: data.armed, injected: data.injected, lastError: data.lastError });
        setVars({ unknown: data.unknownVariables || [], malformed: data.malformedVariables || [] });
        setCfgKeys(data.unknownConfigKeys || []);
      };

      // Best-effort current conversation detection: scan localStorage keys containing session for the first session-<uuid>.
      const guessSession = () => {
        if (sessionIdHint) return sessionIdHint;
        try {
          for (let i = 0; i < localStorage.length; i += 1) {
            const key = localStorage.key(i) || "";
            if (!/session/i.test(key)) continue;
            const raw = localStorage.getItem(key) || "";
            const hit = /session-[0-9a-f-]{36}/i.exec(raw);
            if (hit) return hit[0];
          }
        } catch (_) { /* ignore */ }
        return "";
      };

      const loadSessions = react.useCallback(async () => {
        try {
          const resp = await fetch(SESSIONS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          const list = Array.isArray(json && json.sessions) ? json.sessions : [];
          setSessions(list);
          setPick((prev) => prev || (list.some((x) => x.id === guessSession()) ? guessSession() : (list[0] && list[0].id) || ""));
        } catch (_) { /* ignore */ }
      }, []);
      const load = react.useCallback(async () => {
        try {
          const resp = await fetch(CONFIG_URL, { headers: { accept: "application/json" } });
          const data = await resp.json();
          if (!resp.ok || !data || data.ok === false) { setState("error"); return; }
          const c = data.config || EMPTY;
          setCfg(c);
          setSavedCfg(c);
          setFile(data.path || "");
          setStale(data.proto !== EXPECT_PROTO);
          applyStatus(data);
          setState("ready");
        } catch (e) { setState("error"); }
      }, []);

      react.useEffect(() => { load(); }, [load]);

      const loadPreview = react.useCallback(async (kind) => {
        setPreviewBusy(true);
        try {
          const resp = await fetch(PREVIEW_URL, { headers: { accept: "application/json" } });
          const data = await resp.json();
          if (!resp.ok || !data || data.ok === false) throw new Error((data && data.message) || ("HTTP " + resp.status));
          // Older host APIs return only text: fall back to that instead of an unexplained empty box.
          const fromNew = kind === "effective" ? data.effective : data.official;
          const text = fromNew !== undefined ? fromNew : data.text;
          setPreview({ kind: kind, text: String(text || "(empty)") });
          setStale(data.proto !== EXPECT_PROTO);
          applyStatus(data);
        } catch (e) {
          setPreview({ kind: kind, text: L.previewError + ": " + String((e && e.message) || e), error: true });
        } finally { setPreviewBusy(false); }
      }, []);

      // post closes over stale preview state; use a ref for the currently displayed preview type.
      const previewRef = react.useRef(null);
      react.useEffect(() => { previewRef.current = preview; }, [preview]);

      /** Shared write entry point: synchronize saved state and refresh loaded previews on success; on failure return null and show the original error text. */
      const post = async (body) => {
        const payload = {
          enabled: !!body.enabled,
          mode: body.mode === "replace" ? "replace" : "append",
          text: String(body.text || "")
        };
        // Pass cards through only as arrays, and only for card operations; text/toggle operations leave cards alone.
        // The host guards both missing and non-array values (see the POST route in index.js).
        if (Array.isArray(body.cards)) payload.cards = body.cards;
        setBusy(true); setNotice("");
        try {
          const resp = await fetch(CONFIG_URL, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(payload)
          });
          const data = await resp.json();
          if (!resp.ok || !data || data.ok === false) throw new Error((data && data.message) || ("HTTP " + resp.status));
          setSavedCfg(data.config || body);
          applyStatus(data);
          const shown = previewRef.current;
          if (shown && !shown.error) loadPreview(shown.kind); // Loaded previews must not retain stale text.
          return data;
        } catch (e) {
          setNotice(String((e && e.message) || e));
          return null;
        } finally { setBusy(false); }
      };

      /**
       * Toggle / mode changes take effect immediately. Always use the **saved** text
       * to avoid silently writing unfinished edits before the user clicks Save.
       */
      const applyShape = async (patch) => {
        const next = {
          enabled: patch.enabled !== undefined ? patch.enabled : savedCfg.enabled,
          mode: patch.mode !== undefined ? patch.mode : savedCfg.mode,
          text: savedCfg.text
        };
        setCfg((prev) => Object.assign({}, prev, patch));
        const ok = await post(next);
        if (!ok) {
          // On failure, restore the server's actual toggle/mode state; never display an unapplied value.
          setCfg((prev) => Object.assign({}, prev, { enabled: savedCfg.enabled, mode: savedCfg.mode }));
        }
      };

      // ---- Derived state ----
      const liveText = String(savedCfg.text || "");   // Saved text (what the model actually receives)
      const editorText = String(cfg.text || "");      // Editor text (possibly unsaved)
      const dirtyText = editorText !== liveText;
      const cards = Array.isArray(savedCfg.cards) ? savedCfg.cards : [];
      // Current card = exact match with saved text; empty text matches no card to avoid highlighting empty cards.
      const activeCard = liveText !== ""
        ? (cards.find((c) => String(c.text || "") === liveText) || null)
        : null;
      const pendingCard = pending ? (cards.find((c) => c.id === pending.id) || null) : null;
      const cardsGated = busy || stale;               // Old hosts silently drop cards when stale: block all writes.
      const cardUiBusy = cardsGated || !!pendingCard || adding;
      const saveLabel = (activeCard && !stale) ? L.saveTo(activeCard.name) : L.savePlain;

      /** Switch: save and immediately apply the card text; update the editor only after a successful response. */
      const applyCardText = async (card) => {
        const text = String(card.text || "");
        const ok = await post({ enabled: savedCfg.enabled, mode: savedCfg.mode, text: text });
        if (ok) {
          setCfg((prev) => Object.assign({}, prev, { text: text }));
          setCardNotice(L.cardsNoteUsed(card.name));
          setPending(null);
        }
        return ok;
      };

      /** Chip click: switch and apply immediately; pause for unsaved edits and explain all three choices. */
      const useCard = (card) => {
        if (cardUiBusy || !card) return;
        if (activeCard && card.id === activeCard.id) return; // Clicking the current card is a no-op.
        if (dirtyText) { setCardNotice(""); setPending({ kind: "use", id: card.id }); return; }
        return applyCardText(card);
      };

      /** Choice 1, Save to Current Card and Switch: one POST updates the current card and selects the target. */
      const switchSaving = async () => {
        const target = pendingCard;
        if (!target || !activeCard || cardsGated) return;
        const ok = await post({
          enabled: savedCfg.enabled, mode: savedCfg.mode, text: String(target.text || ""),
          cards: cards.map((c) => (c.id === activeCard.id ? Object.assign({}, c, { text: editorText }) : c))
        });
        if (ok) {
          setCfg((prev) => Object.assign({}, prev, { text: String(target.text || "") }));
          setCardNotice(L.cardsNoteSavedSwitched(activeCard.name, target.name));
          setPending(null);
        }
      };

      /** Choice 2, Save as Card and Switch: save editor contents as a new card, then select the target in one POST. */
      const switchForking = async () => {
        const target = pendingCard;
        if (!target || cardsGated || cards.length >= CARDS_MAX) return;
        const name = suggestName(editorText, cards.length);
        const fork = { id: newCardId(), name: name, text: editorText };
        const ok = await post({
          enabled: savedCfg.enabled, mode: savedCfg.mode, text: String(target.text || ""),
          cards: cards.concat([fork])
        });
        if (ok) {
          setCfg((prev) => Object.assign({}, prev, { text: String(target.text || "") }));
          setCardNotice(L.cardsNoteForkedSwitched(name, target.name));
          setPending(null);
        }
      };

      /** Choice 3, Discard and Switch: select the target directly; a successful response overwrites unsaved edits. */
      const switchDiscarding = () => {
        const target = pendingCard;
        if (!target || cardsGated) return;
        return applyCardText(target);
      };

      const openAdd = () => {
        if (cardsGated || cards.length >= CARDS_MAX) return;
        setCardNotice("");
        setPending(null);
        setNewName(suggestName(editorText, cards.length));
        setAdding(true);
      };

      const cancelAdd = () => { setAdding(false); setNewName(""); };

      /** Save as Card: save the current editor contents, including unsaved changes, and activate them. */
      const submitAdd = async () => {
        if (cardsGated || cards.length >= CARDS_MAX) return;
        const name = newName.trim() || suggestName(editorText, cards.length);
        const card = { id: newCardId(), name: name, text: editorText };
        const ok = await post({
          enabled: savedCfg.enabled, mode: savedCfg.mode, text: editorText,
          cards: cards.concat([card])
        });
        if (ok) {
          setCardNotice(L.cardsNoteAdded(name));
          cancelAdd();
        }
      };

      const openRename = (card) => {
        if (cardUiBusy || !card) return;
        setCardNotice("");
        setRenameText(String(card.name || ""));
        setPending({ kind: "rename", id: card.id });
      };

      /** Rename changes only the name, leaving the text and other fields untouched. */
      const submitRename = async () => {
        const target = pendingCard;
        if (!target || cardsGated) return;
        const name = renameText.trim() || target.name;
        const ok = await post({
          enabled: savedCfg.enabled, mode: savedCfg.mode, text: liveText,
          cards: cards.map((c) => (c.id === target.id ? Object.assign({}, c, { name: name }) : c))
        });
        if (ok) {
          setCardNotice(L.cardsNoteRenamed(name));
          setPending(null);
        }
      };

      const openRemove = (card) => {
        if (cardUiBusy || !card) return;
        setCardNotice("");
        setPending({ kind: "remove", id: card.id });
      };

      /** Delete writes to disk after confirmation; deleting the current card leaves its text in place, unassigned. */
      const submitRemove = async () => {
        const target = pendingCard;
        if (!target || cardsGated) return;
        const ok = await post({
          enabled: savedCfg.enabled, mode: savedCfg.mode, text: liveText,
          cards: cards.filter((c) => c.id !== target.id)
        });
        if (ok) {
          setCardNotice(L.cardsNoteRemoved(target.name));
          setPending(null);
        }
      };

      /**
       * Save text: if it comes from a card, **update that card too**, completing the edit/save/synchronize loop.
       * When stale (old host does not recognize cards), save only text; do not pretend the card was saved.
       */
      const save = async () => {
        if (busy) return;
        const target = stale ? null : activeCard;
        const next = { enabled: cfg.enabled, mode: cfg.mode, text: editorText };
        if (target) next.cards = cards.map((c) => (c.id === target.id ? Object.assign({}, c, { text: editorText }) : c));
        const ok = await post(next);
        if (ok && !ok.lastError) setNotice(target ? L.savedToCard(target.name) : L.saved);
      };

      /** Revert changes: restore saved text in the editor without touching the server. */
      const revert = () => setCfg((prev) => Object.assign({}, prev, { text: liveText }));

      /** Lazy-load preview on expansion, once; post automatically refreshes loaded previews when changes apply. */
      const togglePreview = () => {
        const next = !previewOpen;
        setPreviewOpen(next);
        if (next && !preview) loadPreview(previewKind);
      };

      if (state === "loading") return jsx("div", { children: L.loading });
      if (state === "error") return jsx("div", { children: L.unavailable });

      const stView = statusLine(st);
      const currentLabel = activeCard
        ? L.cardsCurrent(activeCard.name, liveText.length)
        : (liveText !== "" ? L.cardsCurrentCustom(liveText.length) : L.cardsCurrentNone);

      return jsxs("div", {
        style: embedded ? Object.assign({}, S.root, { maxWidth: "none", padding: 24 }) : S.root,
        children: [
          // —— Header: title + currently active status ——
          jsxs("div", {
            style: S.head,
            children: [
              jsx("h2", { style: S.h2, children: L.title }),
              stView ? jsx(Tag, {
                tone: stView.tone === "ok" ? "success" : (stView.tone === "error" ? "danger" : "neutral"),
                children: stView.text
              }) : null
            ]
          }),
          jsx("div", { style: S.sub, children: L.sub }),
          stale ? note(L.staleHost, "error") : null,
          cfgKeys.length ? note(L.unknownCfgKeys(cfgKeys.map((k) => "`" + k + "`").join("、")), "error") : null,

          // —— Injection behavior (immediate) ——
          jsxs("div", {
            style: S.row,
            children: [
              jsx(Switch, {
                checked: !!cfg.enabled,
                disabled: busy,
                onChange: (next) => applyShape({ enabled: next }),
                label: L.enabled
              }),
              jsx("span", { style: S.hint, children: L.enabledHint })
            ]
          }),
          jsxs("div", {
            style: S.row,
            children: [
              jsx(SegmentedControl, {
                id: "dsh-prompt-custom-mode",
                value: cfg.mode === "replace" ? "replace" : "append",
                disabled: busy,
                label: L.mode,
                onChange: (next) => applyShape({ mode: next }),
                options: [
                  { value: "append", label: L.modeAppend },
                  { value: "replace", label: L.modeReplace }
                ]
              }),
              jsx("span", { style: S.hint, children: L.modeHint })
            ]
          }),

          // —— Prompt cards: click to switch + create ——
          jsxs("div", {
            style: S.field,
            children: [
              jsxs("div", {
                style: S.row,
                children: [
                  jsx("span", { style: S.fieldTitle, children: L.cardsTitle }),
                  jsx("span", { style: S.hint, children: L.cardsHint }),
                  !adding ? jsx(Button, {
                    variant: "ghost",
                    size: "sm",
                    icon: jsx(IconPlusOutlineRegular, {}),
                    disabled: cardsGated || cards.length >= CARDS_MAX,
                    style: { marginLeft: "auto" },
                    onClick: openAdd,
                    children: L.cardsAdd
                  }) : null,
                  !adding && cards.length >= CARDS_MAX ? jsx("span", { style: S.hint, children: L.cardsLimit }) : null
                ]
              }),
              stale ? note(L.cardsStale, "error") : null,
              cards.length > 0 ? jsxs("div", {
                style: S.row,
                children: [
                  ...cards.map((card) => jsx(Pill, {
                    key: card.id,
                    active: activeCard ? card.id === activeCard.id : false,
                    disabled: cardUiBusy,
                    title: String(card.text || "").length + " characters",
                    onClick: () => useCard(card),
                    children: card.name
                  })),
                  !activeCard && liveText.trim() !== ""
                    ? jsx(Pill, { active: true, children: L.cardsVirtual })
                    : null
                ]
              }) : null,
              cards.length === 0 ? note(L.cardsEmpty, "muted") : null,
              jsxs("div", {
                style: S.row,
                children: [
                  jsx("span", { style: S.hint, children: currentLabel }),
                  activeCard && !pendingCard && !adding ? jsx(Button, {
                    variant: "ghost", size: "sm", disabled: cardsGated,
                    style: { marginLeft: "auto" },
                    onClick: () => openRename(activeCard),
                    children: L.cardsRename
                  }) : null,
                  activeCard && !pendingCard && !adding ? jsx(Button, {
                    variant: "ghost", size: "sm", disabled: cardsGated,
                    onClick: () => openRemove(activeCard),
                    children: L.cardsRemove
                  }) : null
                ]
              }),
              // Inline panels: create / three switch choices / rename / delete; only one is open at a time.
              adding ? jsxs("div", {
                style: S.panel,
                children: [
                  jsx(Input, {
                    value: newName,
                    disabled: busy,
                    placeholder: L.cardsNamePlaceholder,
                    style: { width: 260 },
                    onChange: (e) => setNewName(e.target.value),
                    onKeyDown: (e) => { if (e.key === "Enter") submitAdd(); }
                  }),
                  jsx(Button, { variant: "primary", size: "sm", disabled: busy, onClick: submitAdd, children: L.cardsSave }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: cancelAdd, children: L.cardsCancel }),
                  jsx("span", { style: S.hint, children: L.cardsAddHint })
                ]
              }) : null,
              pending && pending.kind === "use" && pendingCard ? jsxs("div", {
                style: S.warnPanel,
                children: [
                  jsx("span", { style: S.hint, children: L.cardsUseDirty }),
                  jsx(Button, {
                    variant: "primary", size: "sm", disabled: busy,
                    onClick: activeCard ? switchSaving : switchForking,
                    children: activeCard ? L.cardsSwitchSave(activeCard.name) : L.cardsSwitchFork
                  }),
                  activeCard ? jsx(Button, {
                    variant: "ghost", size: "sm", disabled: busy,
                    onClick: switchForking,
                    children: L.cardsSwitchFork
                  }) : null,
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: switchDiscarding, children: L.cardsSwitchDiscard }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => setPending(null), children: L.cardsCancel })
                ]
              }) : null,
              pending && pending.kind === "rename" && pendingCard ? jsxs("div", {
                style: S.panel,
                children: [
                  jsx("span", { style: S.hint, children: L.cardsRenameLabel }),
                  jsx(Input, {
                    value: renameText,
                    disabled: busy,
                    style: { width: 260 },
                    onChange: (e) => setRenameText(e.target.value),
                    onKeyDown: (e) => { if (e.key === "Enter") submitRename(); }
                  }),
                  jsx(Button, { variant: "primary", size: "sm", disabled: busy, onClick: submitRename, children: L.cardsRenameSave }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => setPending(null), children: L.cardsCancel })
                ]
              }) : null,
              pending && pending.kind === "remove" && pendingCard ? jsxs("div", {
                style: S.panel,
                children: [
                  jsx("span", { style: S.hint, children: L.cardsRemoveAsk(pendingCard.name) }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: submitRemove, children: L.cardsRemoveConfirm }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => setPending(null), children: L.cardsCancel })
                ]
              }) : null,
              cardNotice ? jsx("span", { style: S.hint, children: cardNotice }) : null
            ]
          }),

          // —— Text editor ——
          jsxs("div", {
            style: S.field,
            children: [
              jsx("span", { style: S.fieldTitle, children: L.text }),
              jsx("textarea", {
                value: editorText,
                rows: 12,
                spellCheck: false,
                placeholder: "You are a coding agent powered by the {{model}} model. Your working directory is {{cwd}}.",
                style: S.textarea,
                onChange: (e) => setCfg((prev) => Object.assign({}, prev, { text: e.target.value }))
              }),
              jsxs("div", {
                style: S.row,
                children: [
                  jsx(Button, { variant: "primary", disabled: busy, onClick: save, children: busy ? L.saving : saveLabel }),
                  dirtyText ? jsx(Button, { variant: "ghost", disabled: busy, onClick: revert, children: L.revert }) : null,
                  dirtyText ? jsx(Tag, { tone: "warning", children: L.dirtyTag }) : null,
                  notice ? jsx("span", { style: S.hint, children: notice }) : null
                ]
              }),
              jsx("span", { style: S.hint, children: L.textHint })
            ]
          }),

          // —— Variable warnings (core renderPrompt throws on unknown variables; warn in advance) ——
          vars.malformed.length ? note(L.varMalformed(vars.malformed.map((n) => "{{" + n + "}}").join("、")), "warn") : null,
          vars.unknown.length ? note(L.varWarn(vars.unknown.map((n) => "{{" + n + "}}").join("、")), "warn") : null,

          // —— Preview (one collapsed row; fetch on demand when expanded) ——
          jsx(DisclosureRow, {
            icon: jsx(IconChevronDownOutlineRegular, {}),
            title: L.previewTitle,
            open: previewOpen,
            expandable: true,
            // Make the entire row clickable and keyboard-accessible; default false leaves only a tiny, hard-to-find leading arrow.
            expandOnRowClick: true,
            onToggle: togglePreview,
            children: previewOpen ? [
              jsxs("div", {
                style: S.row,
                children: [
                  jsx(SegmentedControl, {
                    id: "dsh-prompt-custom-preview",
                    value: previewKind,
                    disabled: previewBusy,
                    label: L.previewTitle,
                    onChange: (next) => { setPreviewKind(next); loadPreview(next); },
                    options: [
                      { value: "official", label: L.previewOfficial },
                      { value: "effective", label: L.previewEffective }
                    ]
                  }),
                  jsx(Button, {
                    variant: "ghost", size: "sm", disabled: previewBusy,
                    onClick: () => loadPreview(previewKind),
                    children: previewBusy ? L.previewing : L.previewReload
                  }),
                  jsx("span", { style: S.hint, children: previewKind === "effective" ? L.previewHintEffective : L.previewHintOfficial })
                ]
              }),
              preview && preview.error
                ? note(preview.text, "error")
                : jsx("textarea", {
                    value: preview && !preview.error ? preview.text : "",
                    readOnly: true,
                    rows: 14,
                    spellCheck: false,
                    style: S.mono
                  }),
              preview && !preview.error && preview.kind === "effective" && !(st && st.injected)
                ? note(L.previewNoAgent, "muted")
                : null
            ] : null
          }),

          file ? jsx("div", { style: S.hint, children: L.storage + ": " + file }) : null
        ]
      });
    }

    const PANEL_CSS = [
      ".dsh-fuj-settings-trigger{position:absolute;right:calc(100% + 8px);top:0;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;box-sizing:border-box;margin:0;padding:0;border:1px solid var(--dsw-alias-border-l3,#dfe2e5);border-radius:6px;background:var(--dsw-alias-bg-layer-2,#fff);color:var(--dsw-alias-label-secondary,#68707b);cursor:pointer;pointer-events:auto}",
      ".dsh-fuj-settings-trigger:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(120,128,140,.08));color:var(--dsw-alias-label-primary,#20252b)}",
      ".dsh-fuj-settings-trigger:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary,#169760);outline-offset:3px}",
      ".dsh-fuj-panel.dsh-fuj-panel{width:min(900px,100%);height:min(720px,calc(100dvh - 64px));max-height:100%;padding:0;gap:0;border-radius:16px;background:var(--dsw-alias-bg-layer-2,#fff);color:var(--dsw-alias-label-primary,#20252b)}",
      ".dsh-fuj-panel-layout{display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden}",
      ".dsh-fuj-panel-header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex:none;padding:18px 20px 16px 24px}",
      ".dsh-fuj-panel-heading{display:flex;align-items:center;gap:10px;min-width:0}",
      ".dsh-fuj-panel-title{margin:0;font-size:18px;line-height:26px;font-weight:600}",
      ".dsh-fuj-panel-subtitle{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      ".dsh-fuj-panel-navigation{flex:none;padding:0 24px 16px;border-bottom:1px solid var(--dsw-alias-border-l3,#e5e7eb)}",
      ".dsh-fuj-panel-tabs{width:620px;max-width:100%}",
      ".dsh-fuj-panel-content{flex:1;min-height:0;overflow:auto;overscroll-behavior:contain}",
      ".dsh-fuj-skills{padding:24px;min-height:340px;box-sizing:border-box}",
      ".dsh-fuj-skills-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}",
      ".dsh-fuj-skills-heading h3{margin:0;font-size:16px;line-height:24px;font-weight:600}",
      ".dsh-fuj-skills-count{font-size:12px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      ".dsh-fuj-skills-caption{margin:8px 0 20px;font-size:12px;line-height:19px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      ".dsh-fuj-skill-card{display:flex;flex-direction:column;gap:18px;padding:20px;border:1px solid var(--dsw-alias-border-l3,#e5e7eb);border-radius:12px;background:var(--dsw-alias-bg-layer-2,#fff)}",
      ".dsh-fuj-skill-main{display:flex;align-items:flex-start;gap:14px;min-width:0}",
      ".dsh-fuj-skill-art{display:flex;align-items:center;justify-content:center;flex:none;width:42px;height:42px;border-radius:12px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,128,140,.07));color:var(--dsw-alias-label-secondary,#68707b)}",
      ".dsh-fuj-skill-info{flex:1;min-width:0}",
      ".dsh-fuj-skill-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}",
      ".dsh-fuj-skill-title h4{margin:0;font-size:15px;line-height:22px;font-weight:600}",
      ".dsh-fuj-skill-status{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      ".dsh-fuj-skill-status[data-enabled=true]{color:#169760}",
      ".dsh-fuj-skill-status[data-error=true]{color:var(--dsw-alias-label-error,#b42318)}",
      ".dsh-fuj-skill-project{margin:4px 0 0;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary,#68707b)}",
      ".dsh-fuj-skill-source{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:6px;font-size:12px;line-height:18px}",
      ".dsh-fuj-skill-source a{color:var(--dsw-alias-label-secondary,#68707b);text-underline-offset:3px}",
      ".dsh-fuj-skill-bottom{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding-top:15px;border-top:1px solid var(--dsw-alias-border-l3,#e5e7eb)}",
      ".dsh-fuj-skill-hint{font-size:12px;line-height:19px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      ".dsh-fuj-skill-actions{display:flex;align-items:center;gap:12px;margin-left:auto}",
      ".dsh-fuj-skill-enable{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dsw-alias-label-secondary,#68707b)}",
      ".dsh-fuj-skills-error{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 16px;padding:10px 12px;border-radius:8px;background:rgba(180,35,24,.06);color:var(--dsw-alias-label-error,#b42318);font-size:12px;line-height:19px}",
      ".dsh-fuj-skill-message{margin:0;color:var(--dsw-alias-label-secondary,#68707b);font-size:12px;line-height:19px;overflow-wrap:anywhere}",
      ".dsh-fuj-skill-message[data-error=true]{color:var(--dsw-alias-label-error,#b42318)}",
      ".dsh-fuj-skill-progress{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:8px 12px;margin:12px 0 0}",
      ".dsh-fuj-skill-progress-track{position:relative;grid-column:1/-1;display:block;width:100%;height:6px;overflow:hidden;border:0;border-radius:999px;background:var(--dsw-alias-bg-layer-3,#edf0f2);color:var(--dsw-alias-state-business-primary,#2788d9);appearance:none}",
      ".dsh-fuj-skill-progress-track::-webkit-progress-bar{border-radius:999px;background:var(--dsw-alias-bg-layer-3,#edf0f2)}",
      ".dsh-fuj-skill-progress-track::-webkit-progress-value{border-radius:999px;background:currentColor;transition:width 180ms ease}",
      ".dsh-fuj-skill-progress-track::-moz-progress-bar{border-radius:999px;background:currentColor}",
      ".dsh-fuj-skill-progress[data-indeterminate=true] .dsh-fuj-skill-progress-track::after{content:\"\";position:absolute;inset:0 auto 0 0;width:35%;border-radius:999px;background:currentColor;animation:dsh-fuj-progress 1.15s ease-in-out infinite alternate}",
      "@keyframes dsh-fuj-progress{from{transform:translateX(-5%)}to{transform:translateX(190%)}}",
      ".dsh-fuj-skill-progress-stage,.dsh-fuj-skill-progress-value{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#68707b)}",
      ".dsh-fuj-skill-progress-value{font-variant-numeric:tabular-nums}",
      ".dsh-fuj-skill-cancel{margin-left:auto}",
      ".dsh-fuj-skills-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;min-height:280px;text-align:center}",
      ".dsh-fuj-skills-icon{display:flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:16px;background:var(--dsw-alias-interactive-bg-hover,rgba(120,128,140,.07));color:var(--dsw-alias-label-secondary,#68707b)}",
      ".dsh-fuj-skills-empty p{margin:0;font-size:14px;line-height:22px}",
      ".dsh-fuj-skills-empty small{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary,#8a919a)}",
      "@media(max-width:600px){.dsh-fuj-panel-header{padding:16px}.dsh-fuj-panel-navigation{padding:0 16px 14px}.dsh-fuj-panel-subtitle{display:none}}"
    ].join("\n");

    const REA_CATALOG = {
      id: "rea",
      name: "Reverse Engineering",
      projectName: "Reverse Engineer Anything (REA)",
      repositoryUrl: "https://github.com/morluto/rea",
      installUrl: "https://registry.npmjs.org/rea-agents/latest",
      installed: false,
      enabled: false,
      busy: false,
      phase: "not_installed",
      version: null,
      message: null,
      progress: null,
      tools: 0
    };

    const ABOUTSECURITY_CATALOG = {
      id: "aboutsecurity",
      name: "Penetration Testing",
      projectName: "WgpSec AboutSecurity",
      repositoryUrl: "https://github.com/wgpsec/AboutSecurity",
      installUrl: "https://codeload.github.com/wgpsec/AboutSecurity/zip/refs/heads/master",
      installed: false,
      enabled: false,
      busy: false,
      phase: "not_installed",
      version: null,
      skillCount: 0,
      message: null,
      progress: null,
      tools: 0
    };
    // Knowledge base: content ships with the plugin (plugin/knowledge/); no download, installation, or deletion.
    const KNOWLEDGE_CATALOG = {
      id: "knowledge",
      name: "Knowledge Base",
      projectName: "CVE / PoC Vulnerability Knowledge Base",
      repositoryUrl: null,
      installUrl: null,
      installed: true,
      enabled: false,
      busy: false,
      phase: "disabled",
      version: null,
      skillCount: null,
      entries: null,
      message: null,
      progress: null,
      tools: 0
    };

    const SKILL_CATALOG = [KNOWLEDGE_CATALOG, REA_CATALOG, ABOUTSECURITY_CATALOG];
    const SKILL_IDS = new Set(SKILL_CATALOG.map((item) => item.id));

    function SkillLibrary({ active }) {
      const [items, setItems] = react.useState([]);
      const [loading, setLoading] = react.useState(true);
      const [error, setError] = react.useState("");
      const [actionId, setActionId] = react.useState(null);
      const [refreshIndex, setRefreshIndex] = react.useState(0);
      const actionLock = react.useRef(false);
      const mounted = react.useRef(true);

      react.useEffect(() => {
        mounted.current = true;
        return () => { mounted.current = false; };
      }, []);

      const decode = async (resp) => {
        if (resp.status === 404 || resp.status === 501 || resp.status === 503) {
          throw new Error("Skill library unavailable. Update the plugin and fully restart DSH.");
        }
        let data;
        try { data = await resp.json(); } catch { throw new Error("Failed to read skill library status. Please retry."); }
        const skills = data && Array.isArray(data.skills) ? data.skills.filter((item) => item && SKILL_IDS.has(item.id)) : null;
        if (!resp.ok || !data || data.ok === false || !skills || !skills.length) {
          const failure = new Error(data && data.message ? String(data.message).slice(0, 180) : "Skill library operation failed. Please retry.");
          // Conflict responses can include the authoritative in-progress snapshot.
          // Keep it so the card follows the existing operation instead of its stale state.
          if (skills && skills.length) failure.skills = skills;
          throw failure;
        }
        return skills;
      };

      react.useEffect(() => {
        if (!active) return;
        let cancelled = false;
        let timer;
        const controller = new AbortController();
        const refresh = async () => {
          try {
            const resp = await fetch(SKILLS_URL, {
              headers: { accept: "application/json" },
              signal: controller.signal
            });
            const skills = await decode(resp);
            if (cancelled) return;
            setItems(skills);
            setLoading(false);
            setError("");
            if (skills.some((skill) => skill.busy)) timer = setTimeout(refresh, 1500);
          } catch (cause) {
            if (cancelled) return;
            setLoading(false);
            setError(String(cause && cause.message || "Failed to read skill library status. Please retry."));
            if (cause && cause.skills) {
              setItems(cause.skills);
              if (cause.skills.some((skill) => skill.busy)) timer = setTimeout(refresh, 1500);
            }
          }
        };
        refresh();
        return () => { cancelled = true; controller.abort(); clearTimeout(timer); };
      }, [active, refreshIndex]);

      const act = async (skill, action) => {
        const cancelling = action === "cancel";
        if (actionLock.current || (skill.busy && !cancelling)) return;
        if (cancelling && (!skill.busy || skill.phase !== "installing" || skill.canCancel !== true)) return;
        actionLock.current = true;
        setActionId(skill.id);
        setError("");
        try {
          const resp = await fetch(SKILLS_URL, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ id: skill.id, action })
          });
          const skills = await decode(resp);
          if (!mounted.current) return;
          setItems(skills);
          setRefreshIndex((current) => current + 1);
        } catch (cause) {
          if (mounted.current) {
            setError(String(cause && cause.message || "Skill library operation failed. Please retry."));
            if (cause && cause.skills) {
              setItems(cause.skills);
              if (cause.skills.some((item) => item.busy)) setRefreshIndex((current) => current + 1);
            }
          }
        } finally {
          actionLock.current = false;
          if (mounted.current) setActionId(null);
        }
      };

      // The knowledge base now has its own tab; list only downloadable libraries here.
      const visible = (items.length ? items : SKILL_CATALOG).filter((item) => item.id !== "knowledge");
      const phaseLabel = (skill) => {
        if (loading) return "Loading…";
        const phases = {
          not_installed: "Not installed", installing: "Downloading…", cancelling: "Cancelling…", enabling: "Injecting…",
          disabling: "Disabling…", deleting: "Deleting…", cancelled: "Cancelled", ready: "Enabled", disabled: "Disabled", error: "Failed"
        };
        return phases[skill.phase] || (skill.enabled ? "Enabled" : skill.installed ? "Disabled" : "Not installed");
      };
      const formatBytes = (value) => {
        if (value == null || value === "") return null;
        const bytes = Number(value);
        if (!Number.isFinite(bytes) || bytes < 0) return null;
        if (bytes < 1024) return bytes + " B";
        const units = ["KB", "MB", "GB"];
        let size = bytes / 1024;
        let unit = units[0];
        for (let i = 1; size >= 1024 && i < units.length; i++) { size /= 1024; unit = units[i]; }
        return size.toFixed(size >= 10 ? 0 : 1) + " " + unit;
      };
      const progressInfo = (skill) => {
        const progress = skill.progress && typeof skill.progress === "object" ? skill.progress : {};
        const percentValue = Number(progress.percent);
        const determinate = progress.percent != null && progress.percent !== "" && Number.isFinite(percentValue) && percentValue >= 0 && percentValue <= 100;
        const percent = determinate ? Math.round(percentValue) : null;
        const received = formatBytes(progress.receivedBytes);
        const total = formatBytes(progress.totalBytes);
        const amount = received && total ? received + " / " + total : received ? received + " downloaded" : null;
        const stages = { metadata: "Connecting to official source", package: "Downloading REA", archive: "Downloading skill library", extracting: "Extracting skill files", download: "Downloading REA", dependencies: "Installing dependencies", install: "Installing dependencies", registering: "Registering skills and tools", cancelling: "Cancelling" };
        const stage = stages[progress.stage] || (typeof progress.stage === "string" && progress.stage ? progress.stage : skill.message || "Downloading and installing");
        return { determinate, percent, amount, stage, value: determinate ? percent : undefined };
      };

      return jsxs("div", {
        className: "dsh-fuj-skills",
        children: [
          jsxs("div", {
            className: "dsh-fuj-skills-heading",
            children: [
              jsx("h3", { children: L.skillsTitle }),
              jsx("span", { className: "dsh-fuj-skills-count", children: "Installed " + visible.filter((item) => item.installed).length + " / " + visible.length })
            ]
          }),
          jsx("p", { className: "dsh-fuj-skills-caption", children: "The knowledge base is bundled with the plugin (offline CVE / PoC content); other skills download and install from official sources. Enable them to use them in conversations." }),
          error ? jsxs("div", {
            role: "alert",
            className: "dsh-fuj-skills-error",
            children: [
              jsx("span", { children: error }),
              jsx(Button, { variant: "ghost", size: "sm", onClick: () => setRefreshIndex((value) => value + 1), disabled: !!actionId, children: "Retry" })
            ]
          }) : null,
          visible.map((skill) => {
            const busy = loading || skill.busy || actionId === skill.id;
            const unavailable = !items.length || !!error;
            return jsxs("article", {
              className: "dsh-fuj-skill-card",
              "data-skill-id": skill.id,
              "aria-busy": busy,
              children: [
                jsxs("div", {
                  className: "dsh-fuj-skill-main",
                  children: [
                    jsx("div", { className: "dsh-fuj-skill-art", "aria-hidden": true, children: jsx(IconSkillOutlineRegular, { size: 24 }) }),
                    jsxs("div", {
                      className: "dsh-fuj-skill-info",
                      children: [
                        jsxs("div", {
                          className: "dsh-fuj-skill-title",
                          children: [
                            jsx("h4", { children: skill.name || SKILL_CATALOG.find((item) => item.id === skill.id)?.name || skill.id }),
                            jsx("span", { role: "status", className: "dsh-fuj-skill-status", "data-enabled": !!skill.enabled && !skill.busy, "data-error": skill.phase === "error", children: phaseLabel(skill) })
                          ]
                        }),
                        jsx("p", { className: "dsh-fuj-skill-project", children: skill.projectName || SKILL_CATALOG.find((item) => item.id === skill.id)?.projectName || "" }),
                        jsxs("div", {
                          className: "dsh-fuj-skill-source",
                          children: skill.id === "knowledge" ? [
                            jsx("span", { className: "dsh-fuj-skill-hint", children: "Offline content bundled with the plugin" }),
                            skill.skillCount ? jsx("span", { className: "dsh-fuj-skill-hint", children: skill.skillCount + " categories" }) : null,
                            skill.entries ? jsx("span", { className: "dsh-fuj-skill-hint", children: skill.entries + " vulnerabilities" }) : null
                          ] : [
                            jsx("a", { href: skill.repositoryUrl || "#", target: "_blank", rel: "noreferrer noopener", children: skill.id === "rea" ? "morluto/rea ↗" : "wgpsec/AboutSecurity ↗" }),
                            jsx("a", { href: skill.installUrl || skill.repositoryUrl || "#", target: "_blank", rel: "noreferrer noopener", children: "Download latest version ↗" }),
                            skill.version ? jsx("span", { className: "dsh-fuj-skill-hint", children: "v" + skill.version }) : null,
                            skill.skillCount ? jsx("span", { className: "dsh-fuj-skill-hint", children: skill.skillCount + " skills" }) : null
                          ]
                        })
                      ]
                    })
                  ]
                }),
                skill.message && !(skill.busy && ["installing", "cancelling"].includes(skill.phase)) ? jsx("p", { role: skill.phase === "error" ? "alert" : "status", className: "dsh-fuj-skill-message", "data-error": skill.phase === "error", children: String(skill.message).slice(0, 240) }) : null,
                skill.busy && ["installing", "cancelling"].includes(skill.phase) ? (() => {
                  const progress = progressInfo(skill);
                  const label = [progress.stage, progress.amount].filter(Boolean).join(" · ");
                  return jsxs("div", {
                    className: "dsh-fuj-skill-progress",
                    "data-indeterminate": !progress.determinate,
                    role: "group",
                    "aria-label": (skill.projectName || skill.name || "Skill") + " download progress",
                    children: [
                      jsx("progress", { className: "dsh-fuj-skill-progress-track", max: 100, value: progress.value, "aria-label": "Download and installation progress" }),
                      jsx("span", { className: "dsh-fuj-skill-progress-stage", children: label || progress.stage }),
                      jsx("span", { className: "dsh-fuj-skill-progress-value", children: progress.percent === null ? "Processing…" : progress.percent + "%" })
                    ]
                  });
                })() : null,
                jsxs("div", {
                  className: "dsh-fuj-skill-bottom",
                  children: [
                    jsx("span", {
                      className: "dsh-fuj-skill-hint",
                      children: skill.busy ? "Status updates automatically when the operation finishes."
                        : skill.id === "knowledge"
                          ? (skill.enabled ? "Injected: the model can invoke these categories directly from the skills catalog." : "Bundled content: enable it so the model can find and invoke it in the skills catalog.")
                          : skill.enabled ? "Injected and available in conversations." : skill.installed ? "Injected when enabled; downloaded files are kept when disabled." : "Downloads from the official source and installs automatically."
                    }),
                    skill.busy && skill.phase === "installing" && skill.canCancel === true ? jsx(Button, {
                      variant: "ghost", size: "sm", className: "dsh-fuj-skill-cancel",
                      disabled: actionId === skill.id,
                      onClick: () => act(skill, "cancel"),
                      children: actionId === skill.id ? "Cancelling…" : "Cancel download"
                    }) : skill.installed ? jsxs("div", {
                      className: "dsh-fuj-skill-actions",
                      children: [
                        jsxs("div", {
                          className: "dsh-fuj-skill-enable",
                          children: [
                            jsx("span", { children: skill.enabled ? "Enabled" : "Disabled" }),
                            jsx(Switch, { label: "Enable " + (skill.name || "skill"), checked: !!skill.enabled, disabled: busy || unavailable, onChange: (next) => act(skill, next ? "enable" : "disable") })
                          ]
                        }),
                        skill.id === "knowledge" ? null : jsx(Button, { variant: "ghost", size: "sm", disabled: busy || unavailable, onClick: () => act(skill, "delete"), children: "Delete" })
                      ]
                    }) : jsx(Button, {
                      variant: "primary", size: "sm", disabled: busy || unavailable,
                      onClick: () => act(skill, "install"), children: skill.busy ? phaseLabel(skill) : "Download and install"
                    })
                  ]
                })
              ]
            }, skill.id);
          })
        ]
      });
    }

    const STAGE_LABEL = { recon: "Reconnaissance", fingerprint: "Fingerprinting", match: "Vulnerability Matching", verify: "Feasibility Validation", exploit: "Exploitation", lateral: "Lateral Movement", report: "Reporting" };
    const STAGE_ORDER = ["recon", "fingerprint", "match", "verify", "exploit", "lateral", "report"];

    function CampaignPanel({ active, sessionIdHint }) {
      const [data, setData] = react.useState(null);
      const [detail, setDetail] = react.useState(null);
      const [creating, setCreating] = react.useState(false);
      const [draftName, setDraftName] = react.useState("");
      const [draftScope, setDraftScope] = react.useState("");
      const [confirmDelete, setConfirmDelete] = react.useState("");
      const [notice, setNotice] = react.useState("");
      const [sessions, setSessions] = react.useState([]);
      const [pick, setPick] = react.useState("");
      const [busy, setBusy] = react.useState(false);
      const [error, setError] = react.useState("");

      // Best-effort current conversation detection: scan localStorage keys containing session for the first session-<uuid>.
      const guessSession = () => {
        if (sessionIdHint) return sessionIdHint;
        try {
          for (let i = 0; i < localStorage.length; i += 1) {
            const key = localStorage.key(i) || "";
            if (!/session/i.test(key)) continue;
            const raw = localStorage.getItem(key) || "";
            const hit = /session-[0-9a-f-]{36}/i.exec(raw);
            if (hit) return hit[0];
          }
        } catch (_) { /* ignore */ }
        return "";
      };

      const loadSessions = react.useCallback(async () => {
        try {
          const resp = await fetch(SESSIONS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          const list = Array.isArray(json && json.sessions) ? json.sessions : [];
          setSessions(list);
          setPick((prev) => prev || (list.some((x) => x.id === guessSession()) ? guessSession() : (list[0] && list[0].id) || ""));
        } catch (_) { /* ignore */ }
      }, []);
      const load = react.useCallback(async () => {
        try {
          const resp = await fetch(CAMPAIGNS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setData(json);
          setError("");
        } catch (e) { setError(String((e && e.message) || e)); }
      }, []);

      const open = react.useCallback(async (id) => {
        try {
          const resp = await fetch(CAMPAIGNS_URL + "?id=" + encodeURIComponent(id), { headers: { accept: "application/json" } });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setDetail(json);
          setError("");
        } catch (e) { setError(String((e && e.message) || e)); }
      }, []);

      react.useEffect(() => { if (active) { load(); loadSessions(); } }, [active, load, loadSessions]);

      const post = async (body) => {
        setBusy(true); setError("");
        try {
          const resp = await fetch(CAMPAIGNS_URL, {
            method: "POST",
            headers: { "content-type": "application/json", "x-dsh-ui": "1" },
            body: JSON.stringify(body)
          });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setNotice(json.kicked === true ? L.taskKicked : (json.kickReason ? L.taskKickHint + json.kickReason : ""));
          await load();
          if (body.id && body.action !== "delete") await open(body.id);
          if (body.action === "delete") setDetail(null);
          return true;
        } catch (e) { setError(String((e && e.message) || e)); return false; }
        finally { setBusy(false); }
      };

      const submitCreate = async () => {
        const name = draftName.trim();
        if (!name) return;
        const domains = draftScope.split(/[\s,，;]+/).map((x) => x.trim()).filter(Boolean);
        if (await post({ action: "create", name, scope: { domains } })) {
          setCreating(false); setDraftName(""); setDraftScope("");
        }
      };
      const stageBar = (current) => {
        const index = STAGE_ORDER.indexOf(current);
        return jsxs("div", {
          style: { display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", padding: "2px 0" },
          children: [
            jsx("span", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)" }, children: L.taskProgress }),
            ...STAGE_ORDER.map((key, i) => {
              const done = i < index;
              const now = i === index;
              const color = now ? "#175cd3" : (done ? "#169760" : "var(--dsw-alias-label-tertiary)");
              const bg = now ? "rgba(23,92,211,.10)" : (done ? "rgba(22,151,96,.10)" : "transparent");
              return jsxs("span", {
                key,
                style: {
                  display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 999,
                  fontSize: 12, lineHeight: "20px", color, background: bg,
                  border: "1px solid " + (now ? "#175cd3" : (done ? "#169760" : "var(--dsw-alias-border-l3)")),
                  fontWeight: now ? 600 : 400
                },
                children: [(done ? "✓ " : (i + 1) + " ") + (STAGE_LABEL[key] || key)]
              }, key);
            })
          ]
        });
      };
      const items = data && Array.isArray(data.items) ? data.items : [];
      const current = detail && detail.campaign ? detail.campaign : null;
      const next = detail && detail.next ? detail.next : null;

      return jsxs("div", {
        className: "dsh-fuj-skills",
        children: [
          jsxs("div", {
            className: "dsh-fuj-skills-heading",
            children: [
              jsx("h3", { children: L.taskTitle }),
              jsx(Button, { variant: "primary", size: "sm", disabled: busy || creating, onClick: () => setCreating(true), children: L.taskNew })
            ]
          }),
          error ? jsxs("div", {
            role: "alert",
            className: "dsh-fuj-skills-error",
            children: [jsx("span", { children: error }), jsx(Button, { variant: "ghost", size: "sm", onClick: load, disabled: busy, children: "Retry" })]
          }) : null,
          creating ? jsxs("article", {
            className: "dsh-fuj-skill-card",
            style: { gap: 10, marginBottom: 10 },
            children: [
              jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)" }, children: L.taskCreateHint }),
              jsx(Input, {
                value: draftName,
                placeholder: L.taskNamePlaceholder,
                onChange: (e) => setDraftName(e.target.value),
                onKeyDown: (e) => { if (e.key === "Enter") submitCreate(); }
              }),
              jsx(Input, {
                value: draftScope,
                placeholder: L.taskScopePlaceholder,
                onChange: (e) => setDraftScope(e.target.value)
              }),
              jsxs("div", {
                style: { display: "flex", gap: 8 },
                children: [
                  jsx(Button, { variant: "primary", size: "sm", disabled: busy || !draftName.trim(), onClick: submitCreate, children: L.taskCreate }),
                  jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => { setCreating(false); setDraftName(""); setDraftScope(""); }, children: L.taskCancel })
                ]
              })
            ]
          }) : null,          ...items.map((item) => {
            const expanded = current && current.id === item.id;
            return jsxs("article", {
              className: "dsh-fuj-skill-card",
              style: { gap: 10, marginBottom: 10 },
              children: [
                jsxs("div", {
                  style: { display: "flex", alignItems: "center", gap: 10, cursor: "pointer" },
                  onClick: () => (expanded ? setDetail(null) : open(item.id)),
                  children: [
                    jsx("span", {
                      style: { flex: "0 0 auto", padding: "1px 8px", borderRadius: 999, fontSize: 12, lineHeight: "20px", color: "#175cd3", background: "rgba(23,92,211,.08)", border: "1px solid #175cd3" },
                      children: STAGE_LABEL[item.stage] || item.stage
                    }),
                    jsxs("div", { style: { minWidth: 0, flex: 1 }, children: [
                      jsx("div", { style: { fontSize: 14, lineHeight: "22px", overflowWrap: "anywhere" }, children: item.name }),
                      jsx("div", { style: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)" }, children: L.taskAssets + " " + item.assets + " · " + L.taskSteps + " " + item.steps + " · " + fmtTime(item.updatedAt) })
                    ]})
                  ]
                }),
                expanded && current ? jsxs("div", {
                  style: { borderTop: "1px solid var(--dsw-alias-border-l3)", paddingTop: 10, display: "flex", flexDirection: "column", gap: 10 },
                  children: [
                    jsx("div", { style: { fontSize: 13, lineHeight: "20px", fontWeight: 600 }, children: (current.done ? "✓ Achieved · " : "") + L.taskObjective + (current.objective || current.name) }),
                    stageBar(current.stage),
                    notice ? jsx("div", { style: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-secondary)" }, children: notice }) : null,
                    current.sessionId
                      ? jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", overflowWrap: "anywhere" }, children: L.taskBound + current.sessionId })
                      : jsxs("div", {
                          style: { display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" },
                          children: [
                            jsx("span", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)" }, children: L.taskBindPick }),
                            jsx("select", {
                              value: pick,
                              onChange: (e) => setPick(e.target.value),
                              style: { height: 28, borderRadius: 6, border: "1px solid var(--dsw-alias-border-l3)", background: "var(--dsw-alias-bg-layer-2)", color: "inherit", fontSize: 12, maxWidth: 260 }
                            }, sessions.length
                              ? sessions.map((x, i) => jsx("option", { value: x.id, title: x.id, children: (x.id === guessSession() ? "★ " : "") + (x.title ? x.title.slice(0, 24) : "Conversation " + (i + 1)) + " · " + x.id.slice(-8) + (x.status === "running" ? " (running)" : "") }, x.id))
                              : jsx("option", { value: "", children: "No online conversations" })),
                            jsx(Button, { variant: "ghost", size: "sm", disabled: busy || !pick, onClick: () => post({ action: "bind", id: current.id, sessionId: pick }), children: L.taskBind }),
                            jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: loadSessions, children: "Refresh" })
                          ]
                        }),
                    jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", overflowWrap: "anywhere" }, children: L.taskScope + "：" + ([current.scope.domains, current.scope.cidrs].flat().filter(Boolean).join(" · ") || "-") }),
                    sessionIdHint ? jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-secondary)", overflowWrap: "anywhere" }, children: "Conversation detected by the panel: " + sessionIdHint }) : null,
                    jsx("div", { style: { fontSize: 12, lineHeight: "18px" }, children: current.assets.length ? current.assets.map((a) => a.host + (a.port ? ":" + a.port : "") + (a.fingerprint ? "（" + a.fingerprint + "）" : "") + " · " + (a.status || "new")).join("\n") : L.taskNoAdvice }),
                    jsx("div", { style: { fontSize: 12, lineHeight: "18px", whiteSpace: "pre-wrap" }, children: current.steps.length ? current.steps.slice(-5).map((st) => "[" + (STAGE_LABEL[st.stage] || st.stage) + "] " + st.action + " → " + st.result).join("\n") : "" }),
                    jsxs("div", {
                      style: { padding: 10, borderRadius: 8, background: "var(--dsw-alias-bg-layer-2)", border: "1px solid var(--dsw-alias-border-l3)" },
                      children: [
                        jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-secondary)", marginBottom: 4 }, children: L.taskSuggest }),
                        jsx("div", { style: { fontSize: 12, lineHeight: "19px", whiteSpace: "pre-wrap" }, children: next && (next.suggestions || []).length ? next.suggestions.map((sg) => sg.text).join("\n") : L.taskNoAdvice })
                      ]
                    }),
                    jsxs("div", {
                      style: { display: "flex", gap: 8, flexWrap: "wrap" },
                      children: [
                        current.sessionId ? jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => post({ action: "kick", id: current.id }), children: L.taskKick }) : null,
                        current.sessionId ? jsx(Button, { variant: "ghost", size: "sm", disabled: busy, onClick: () => post({ action: "unbind", id: current.id }), children: L.taskUnbind }) : null,
                        jsx(Button, {
                          variant: "ghost", size: "sm",
                          disabled: busy || STAGE_ORDER.indexOf(current.stage) <= 0,
                          onClick: () => post({ action: "patch", id: current.id, stage: STAGE_ORDER[STAGE_ORDER.indexOf(current.stage) - 1] }),
                          children: L.taskPrev
                        }),
                        jsx(Button, {
                          variant: "primary", size: "sm", disabled: busy || !next || (next && next.nextStage === current.stage),
                          onClick: () => next && post({ action: "patch", id: current.id, stage: next.nextStage }),
                          children: L.taskNext + (next ? "（" + (STAGE_LABEL[next.nextStage] || next.nextStage) + "）" : "")
                        }),
                        jsx(Button, {
                          variant: "ghost", size: "sm", style: { marginLeft: "auto" }, disabled: busy,
                          onClick: () => {
                            if (confirmDelete !== current.id) { setConfirmDelete(current.id); setTimeout(() => setConfirmDelete(""), 4000); return; }
                            setConfirmDelete(""); post({ action: "delete", id: current.id });
                          },
                          children: confirmDelete === current.id ? "Confirm deletion?" : L.taskDelete
                        })
                      ]
                    })
                  ]
                }) : null
              ]
            }, item.id);
          }),
          data && items.length === 0 ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.taskEmpty }) }) : null,
          !data && !error ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.taskLoading }) }) : null
        ]
      });
    }
    const SEVERITY_META = {
      critical: { label: "Critical", color: "#b42318", bg: "rgba(180,35,24,.08)" },
      high: { label: "High", color: "#d92d20", bg: "rgba(217,45,32,.08)" },
      medium: { label: "Medium", color: "#b54708", bg: "rgba(181,71,8,.08)" },
      low: { label: "Low", color: "#175cd3", bg: "rgba(23,92,211,.08)" },
      info: { label: "Informational", color: "#475467", bg: "rgba(71,84,103,.08)" }
    };
    const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
    const STATUS_LABEL = { open: L.reportStatusOpen, fixed: L.reportStatusFixed, accepted: L.reportStatusAccepted, "false-positive": L.reportStatusFalse };

    function fmtTime(value) {
      const date = new Date(value);
      if (!value || Number.isNaN(date.getTime())) return String(value || "");
      const pad = (n) => (n < 10 ? "0" + n : String(n));
      return pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
    }

    function ReportPanel({ active }) {
      const [data, setData] = react.useState(null);
      const [busy, setBusy] = react.useState(false);
      const [error, setError] = react.useState("");
      const [filter, setFilter] = react.useState("");
      const [query, setQuery] = react.useState("");
      const [expanded, setExpanded] = react.useState("");
      const [hintOpen, setHintOpen] = react.useState(false);
      const [confirmClear, setConfirmClear] = react.useState(false);

      // Best-effort current conversation detection: scan localStorage keys containing session for the first session-<uuid>.
      const guessSession = () => {
        if (sessionIdHint) return sessionIdHint;
        try {
          for (let i = 0; i < localStorage.length; i += 1) {
            const key = localStorage.key(i) || "";
            if (!/session/i.test(key)) continue;
            const raw = localStorage.getItem(key) || "";
            const hit = /session-[0-9a-f-]{36}/i.exec(raw);
            if (hit) return hit[0];
          }
        } catch (_) { /* ignore */ }
        return "";
      };

      const loadSessions = react.useCallback(async () => {
        try {
          const resp = await fetch(SESSIONS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          const list = Array.isArray(json && json.sessions) ? json.sessions : [];
          setSessions(list);
          setPick((prev) => prev || (list.some((x) => x.id === guessSession()) ? guessSession() : (list[0] && list[0].id) || ""));
        } catch (_) { /* ignore */ }
      }, []);
      const load = react.useCallback(async () => {
        try {
          const resp = await fetch(FINDINGS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setData(json);
          setError("");
        } catch (e) { setError(String((e && e.message) || e)); }
      }, []);

      react.useEffect(() => { if (active) { load(); loadSessions(); } }, [active, load, loadSessions]);

      const post = async (body) => {
        setBusy(true); setError("");
        try {
          const resp = await fetch(FINDINGS_URL, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body)
          });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setData(json);
        } catch (e) { setError(String((e && e.message) || e)); }
        finally { setBusy(false); }
      };

      const exportMarkdown = async () => {
        try {
          const resp = await fetch(FINDINGS_MD_URL, { headers: { accept: "text/markdown" } });
          const text = await resp.text();
          const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = "vuln-report.md";
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        } catch (e) { setError(String((e && e.message) || e)); }
      };

      const stats = (data && data.stats) || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, open: 0 };
      const all = data && Array.isArray(data.items) ? data.items : [];
      const keyword = query.trim().toLowerCase();
      const matched = all.filter((item) => {
        if (filter && item.severity !== filter) return false;
        if (!keyword) return true;
        return [item.title, item.target, item.url, item.cve, item.category].filter(Boolean).join(" ").toLowerCase().includes(keyword);
      });
      const groups = SEVERITY_ORDER
        .map((severity) => ({ severity, items: matched.filter((item) => item.severity === severity) }))
        .filter((group) => group.items.length > 0);

      const metricTile = (severity) => {
        const meta = severity ? SEVERITY_META[severity] : null;
        const count = severity ? (stats[severity] || 0) : stats.total;
        const selected = filter === severity;
        return jsx("div", {
          key: severity || "all",
          onClick: () => setFilter(selected ? "" : severity),
          style: {
            flex: "1 1 0", minWidth: 104, cursor: "pointer", padding: "10px 12px", borderRadius: 10,
            border: "1px solid " + (selected ? (meta ? meta.color : "var(--dsw-alias-state-business-primary)") : "var(--dsw-alias-border-l3)"),
            borderLeft: "3px solid " + (meta ? meta.color : "var(--dsw-alias-label-tertiary)"),
            background: selected ? (meta ? meta.bg : "var(--dsw-alias-bg-layer-3)") : "var(--dsw-alias-bg-layer-2)"
          },
          children: [
            jsx("div", { style: { fontSize: 22, lineHeight: "26px", fontWeight: 600, color: meta ? meta.color : "var(--dsw-alias-label-primary)" }, children: String(count) }),
            jsx("div", { style: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)" }, children: (meta ? meta.label : L.reportAll) })
          ]
        }, severity || "all");
      };

      const detailOf = (item) => jsxs("div", {
        style: { padding: "12px 14px", background: "var(--dsw-alias-bg-layer-2)", borderTop: "1px solid var(--dsw-alias-border-l3)", display: "flex", flexDirection: "column", gap: 10 },
        children: [
          item.description ? jsxs("div", { children: [
            jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", marginBottom: 2 }, children: L.reportDetailDescription }),
            jsx("div", { style: { fontSize: 13, lineHeight: "21px", whiteSpace: "pre-wrap" }, children: item.description })
          ]}) : null,
          item.evidence ? jsxs("div", { children: [
            jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", marginBottom: 2 }, children: L.reportDetailEvidence }),
            jsx("pre", {
              style: { margin: 0, padding: "8px 10px", borderRadius: 8, background: "var(--dsw-alias-bg-layer-3)", fontSize: 12, lineHeight: "18px", whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 240, overflow: "auto" },
              children: item.evidence
            })
          ]}) : null,
          item.remediation ? jsxs("div", { children: [
            jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", marginBottom: 2 }, children: L.reportDetailRemediation }),
            jsx("div", { style: { fontSize: 13, lineHeight: "21px", whiteSpace: "pre-wrap" }, children: item.remediation })
          ]}) : null,
          item.references ? jsxs("div", { children: [
            jsx("div", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", marginBottom: 2 }, children: L.reportDetailRefs }),
            jsx("div", { style: { fontSize: 12, lineHeight: "19px", overflowWrap: "anywhere" }, children: item.references })
          ]}) : null,
          jsxs("div", {
            style: { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", paddingTop: 4 },
            children: [
              jsx("span", {
                style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)" },
                children: [item.cve, item.cvss !== null ? L.reportCvss + " " + item.cvss : "", item.verified ? L.reportVerify : L.reportUnverified, L.reportSource + " " + item.source].filter(Boolean).join(" · ")
              }),
              jsx(Button, { variant: "ghost", size: "sm", disabled: busy || item.status === "fixed", onClick: () => post({ action: "status", id: item.id, status: "fixed" }), children: L.reportStatusFixed }),
              jsx(Button, { variant: "ghost", size: "sm", disabled: busy || item.status === "accepted", onClick: () => post({ action: "status", id: item.id, status: "accepted" }), children: L.reportStatusAccepted }),
              jsx(Button, { variant: "ghost", size: "sm", disabled: busy || item.status === "false-positive", onClick: () => post({ action: "status", id: item.id, status: "false-positive" }), children: L.reportStatusFalse }),
              jsx(Button, { variant: "ghost", size: "sm", style: { marginLeft: "auto" }, disabled: busy, onClick: () => post({ action: "delete", id: item.id }), children: L.reportDelete })
            ]
          })
        ]
      });

      return jsxs("div", {
        className: "dsh-fuj-skills",
        children: [
          jsxs("div", {
            className: "dsh-fuj-skills-heading",
            style: { alignItems: "baseline" },
            children: [
              jsx("h3", { children: L.reportTitle }),
              jsx("span", { className: "dsh-fuj-skills-count", children: L.reportTotal(stats.total, stats.open || 0) + (data && data.updatedAt > 0 ? " · " + L.reportUpdated(fmtTime(new Date(data.updatedAt).toISOString())) : "") })
            ]
          }),
          jsx("p", { className: "dsh-fuj-skills-caption", children: L.reportSub }),
          jsx("div", { style: { display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }, children: ["", ...SEVERITY_ORDER].map(metricTile) }),
          jsxs("div", {
            style: { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 6 },
            children: [
              jsx(Input, { value: query, placeholder: L.reportSearchPlaceholder, style: { flex: "1 1 220px", minWidth: 180 }, onChange: (e) => setQuery(e.target.value) }),
              jsx(Button, { variant: "ghost", size: "sm", disabled: busy || !stats.total, onClick: exportMarkdown, children: L.reportExport }),
              jsx(Button, {
                variant: "ghost", size: "sm", disabled: busy || !stats.total,
                onClick: () => { if (!confirmClear) { setConfirmClear(true); setTimeout(() => setConfirmClear(false), 4000); return; } setConfirmClear(false); post({ action: "clear" }); },
                children: confirmClear ? "Confirm clearing?" : L.reportClear
              })
            ]
          }),
          error ? jsxs("div", {
            role: "alert",
            className: "dsh-fuj-skills-error",
            style: { marginTop: 8 },
            children: [
              jsx("span", { children: error }),
              jsx(Button, { variant: "ghost", size: "sm", onClick: load, disabled: busy, children: "Retry" })
            ]
          }) : null,
          ...groups.map((group) => {
            const meta = SEVERITY_META[group.severity];
            return jsxs("div", {
              style: { marginTop: 14 },
              children: [
                jsxs("div", {
                  style: { display: "flex", alignItems: "center", gap: 8, padding: "4px 2px 8px" },
                  children: [
                    jsx("span", { style: { width: 8, height: 8, borderRadius: 999, background: meta.color, display: "inline-block" } }),
                    jsx("span", { style: { fontSize: 13, fontWeight: 600, color: "var(--dsw-alias-label-primary)" }, children: meta.label }),
                    jsx("span", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)" }, children: "（" + group.items.length + "）" })
                  ]
                }),
                jsx("div", {
                  style: { border: "1px solid var(--dsw-alias-border-l3)", borderRadius: 10, overflow: "hidden", background: "var(--dsw-alias-bg-layer-2)" },
                  children: group.items.map((item, index) => {
                    const open = expanded === item.id;
                    return jsxs("div", {
                      children: [
                        jsxs("div", {
                          onClick: () => setExpanded(open ? "" : item.id),
                          style: {
                            display: "grid", gridTemplateColumns: "minmax(0, 1fr) 108px 96px", gap: 12, alignItems: "center",
                            padding: "9px 14px", cursor: "pointer",
                            borderTop: index === 0 ? "none" : "1px solid var(--dsw-alias-border-l4)",
                            background: open ? "var(--dsw-alias-bg-layer-3)" : "transparent"
                          },
                          children: [
                            jsxs("div", {
                              style: { minWidth: 0 },
                              children: [
                                jsx("div", { style: { fontSize: 13, lineHeight: "20px", color: "var(--dsw-alias-label-primary)", overflowWrap: "anywhere" }, children: item.title }),
                                jsx("div", { style: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)", overflowWrap: "anywhere" }, children: [item.target, item.url, item.cve].filter(Boolean).join(" · ") || item.foundAt })
                              ]
                            }),
                            jsx("span", { style: { fontSize: 12, color: item.status === "fixed" ? "#169760" : "var(--dsw-alias-label-secondary)" }, children: STATUS_LABEL[item.status] || item.status }),
                            jsx("span", { style: { fontSize: 12, color: "var(--dsw-alias-label-tertiary)", textAlign: "right" }, children: fmtTime(item.foundAt) })
                          ]
                        }),
                        open ? detailOf(item) : null
                      ]
                    }, item.id);
                  })
                })
              ]
            }, group.severity);
          }),
          !data && !error ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.reportLoading }) }) : null,
          data && stats.total === 0 ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.reportEmpty }) }) : null,
          data && stats.total > 0 && matched.length === 0 ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.reportNoMatch }) }) : null,
          jsx(DisclosureRow, {
            icon: jsx(IconChevronDownOutlineRegular, {}),
            title: L.reportAiHint,
            open: hintOpen,
            expandable: true,
            expandOnRowClick: true,
            onToggle: () => setHintOpen(!hintOpen),
            children: hintOpen ? jsx("pre", {
              style: { margin: 0, padding: 10, borderRadius: 8, background: "var(--dsw-alias-bg-layer-2)", border: "1px solid var(--dsw-alias-border-l3)", fontSize: 12, lineHeight: "18px", whiteSpace: "pre-wrap", overflowWrap: "anywhere" },
              children: [
                "curl -s -X POST " + (typeof location !== "undefined" ? location.origin : "http://127.0.0.1:54429") + "/api/dsh-prompt-custom/findings \\",
                "  -H 'content-type: application/json' \\",
                "  -d '{\"action\":\"upsert\",\"title\":\"SQL injection\",\"severity\":\"high\",\"target\":\"api.example.com\",\"url\":\"/api/order?id=1\",\"evidence\":\"1' AND SLEEP(3)-- 3s delay\",\"remediation\":\"Parameterized queries\"}'"
              ].join("\n")
            }) : null
          })
        ]
      });
    }
    function KnowledgePanel({ active }) {
      const [data, setData] = react.useState(null);
      const [busy, setBusy] = react.useState(false);
      const [error, setError] = react.useState("");
      const [open, setOpen] = react.useState("");

      // Best-effort current conversation detection: scan localStorage keys containing session for the first session-<uuid>.
      const guessSession = () => {
        if (sessionIdHint) return sessionIdHint;
        try {
          for (let i = 0; i < localStorage.length; i += 1) {
            const key = localStorage.key(i) || "";
            if (!/session/i.test(key)) continue;
            const raw = localStorage.getItem(key) || "";
            const hit = /session-[0-9a-f-]{36}/i.exec(raw);
            if (hit) return hit[0];
          }
        } catch (_) { /* ignore */ }
        return "";
      };

      const loadSessions = react.useCallback(async () => {
        try {
          const resp = await fetch(SESSIONS_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          const list = Array.isArray(json && json.sessions) ? json.sessions : [];
          setSessions(list);
          setPick((prev) => prev || (list.some((x) => x.id === guessSession()) ? guessSession() : (list[0] && list[0].id) || ""));
        } catch (_) { /* ignore */ }
      }, []);
      const load = react.useCallback(async () => {
        try {
          const resp = await fetch(KNOWLEDGE_URL, { headers: { accept: "application/json" } });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          setData(json);
          setError("");
        } catch (e) { setError(String((e && e.message) || e)); }
      }, []);

      react.useEffect(() => { if (active) { load(); loadSessions(); } }, [active, load, loadSessions]);

      const toggle = async (next) => {
        if (busy) return;
        setBusy(true); setError("");
        try {
          const resp = await fetch(SKILLS_URL, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ id: "knowledge", action: next ? "enable" : "disable" })
          });
          const json = await resp.json();
          if (!resp.ok || !json || json.ok === false) throw new Error((json && json.message) || ("HTTP " + resp.status));
          await load();
        } catch (e) { setError(String((e && e.message) || e)); }
        finally { setBusy(false); }
      };

      const categories = data && Array.isArray(data.categories) ? data.categories : [];
      const total = data && typeof data.total === "number" ? data.total : 0;
      const enabled = !!(data && data.enabled);

      return jsxs("div", {
        className: "dsh-fuj-skills",
        children: [
          jsxs("div", {
            className: "dsh-fuj-skills-heading",
            children: [
              jsx("h3", { children: L.knowledgeTitle }),
              jsx("span", { className: "dsh-fuj-skills-count", children: enabled ? L.knowledgeTotal(total, categories.length) : "Disabled (" + (data && data.available ? data.available : 0) + " entries available)" })
            ]
          }),
          jsx("p", { className: "dsh-fuj-skills-caption", children: L.knowledgeHint }),
          error ? jsxs("div", {
            role: "alert",
            className: "dsh-fuj-skills-error",
            children: [
              jsx("span", { children: error }),
              jsx(Button, { variant: "ghost", size: "sm", onClick: load, disabled: busy, children: "Retry" })
            ]
          }) : null,
          jsx("article", {
            className: "dsh-fuj-skill-card",
            children: jsxs("div", {
              className: "dsh-fuj-skill-bottom",
              style: { paddingTop: 0, borderTop: "none" },
              children: [
                jsx("span", { className: "dsh-fuj-skill-hint", children: enabled ? L.knowledgeOn : L.knowledgeOff }),
                jsxs("div", {
                  className: "dsh-fuj-skill-enable",
                  children: [
                    jsx("span", { children: enabled ? "Enabled" : "Disabled" }),
                    jsx(Switch, { label: L.knowledgeTitle, checked: enabled, disabled: busy || !data, onChange: toggle })
                  ]
                })
              ]
            })
          }),
          ...categories.map((category) => jsx(DisclosureRow, {
            key: category.name,
            icon: jsx(IconChevronDownOutlineRegular, {}),
            title: category.title + " (" + category.count + " entries)",
            open: open === category.name,
            expandable: true,
            expandOnRowClick: true,
            onToggle: () => setOpen(open === category.name ? "" : category.name),
            children: (category.entries || []).map((entry) => jsxs("div", {
              key: entry.file,
              style: { display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, padding: "5px 0" },
              children: [
                jsxs("div", {
                  style: { minWidth: 0 },
                  children: [
                    jsx("div", { style: { fontSize: 13, lineHeight: "20px", color: "var(--dsw-alias-label-primary)" }, children: entry.title }),
                    jsx("div", { style: { fontSize: 12, lineHeight: "18px", color: "var(--dsw-alias-label-tertiary)", overflowWrap: "anywhere" }, children: entry.entry || entry.file })
                  ]
                }),
                jsx("span", { style: { fontSize: 12, lineHeight: "20px", color: "var(--dsw-alias-label-secondary)" }, children: entry.severity })
              ]
            }))
          }, category.name)),
          !data && !error ? jsx("div", { className: "dsh-fuj-skills-empty", children: jsx("p", { children: L.knowledgeLoading }) }) : null,
          data && categories.length === 0 ? jsxs("div", {
            className: "dsh-fuj-skills-empty",
            children: [jsx("p", { children: L.knowledgeEmpty }), jsx("small", { children: L.knowledgeRestart })]
          }) : null
        ]
      });
    }
    function PluginPanel({ open, onClose, id, sessionId = "" }) {
      const [tab, setTab] = react.useState("prompt");
      const tabId = react.useId();
      const promptTabId = tabId + "-prompt-tab";
      const skillsTabId = tabId + "-skills-tab";
      const promptPanelId = tabId + "-prompt-panel";
      const skillsPanelId = tabId + "-skills-panel";
      const reportTabId = tabId + "-report-tab";
      const reportPanelId = tabId + "-report-panel";
      const knowledgeTabId = tabId + "-knowledge-tab";
      const knowledgePanelId = tabId + "-knowledge-panel";
      const campaignTabId = tabId + "-campaign-tab";
      const campaignPanelId = tabId + "-campaign-panel";

      return jsx(Modal, {
        open,
        onClose,
        title: L.pluginSettings,
        headless: true,
        className: "dsh-fuj-panel",
        children: jsxs("div", {
          id,
          className: "dsh-fuj-panel-layout",
          onClick: (event) => event.stopPropagation(),
          children: [
            jsxs("header", {
              className: "dsh-fuj-panel-header",
              children: [
                jsxs("div", {
                  className: "dsh-fuj-panel-heading",
                  children: [
                    jsx("h2", { className: "dsh-fuj-panel-title", children: L.toggleLabel }),
                    jsx("span", { className: "dsh-fuj-panel-subtitle", children: L.pluginSettingsHint })
                  ]
                }),
                jsx(Button, {
                  variant: "ghost",
                  size: "sm",
                  "aria-label": L.closeSettings,
                  title: L.closeSettings,
                  onClick: onClose,
                  icon: jsx(IconCloseOutlineRegular, { size: 16 })
                })
              ]
            }),
            jsx("nav", {
              className: "dsh-fuj-panel-navigation",
              "aria-label": L.pluginFunctions,
              children: jsx(SegmentedTabs, {
                className: "dsh-fuj-panel-tabs",
                label: L.pluginFunctions,
                value: tab,
                onChange: setTab,
                items: [
                  { value: "prompt", label: L.title, id: promptTabId, panelId: promptPanelId },
                  { value: "skills", label: L.skillsTitle, id: skillsTabId, panelId: skillsPanelId },
                  { value: "knowledge", label: L.knowledgeTitle, id: knowledgeTabId, panelId: knowledgePanelId },
                  { value: "report", label: L.reportTitle, id: reportTabId, panelId: reportPanelId },
                  { value: "campaign", label: L.taskTitle, id: campaignTabId, panelId: campaignPanelId }
                ]
              })
            }),
            jsxs("div", {
              className: "dsh-fuj-panel-content",
              children: [
                // Keep the editor mounted while switching tabs so unsaved edits stay intact.
                jsx("section", {
                  id: reportPanelId,
                  role: "tabpanel",
                  "aria-labelledby": reportTabId,
                  hidden: tab !== "report",
                  children: jsx(ReportPanel, { active: open && tab === "report" })
                }),
                jsx("section", {
                  id: promptPanelId,
                  role: "tabpanel",
                  "aria-labelledby": promptTabId,
                  hidden: tab !== "prompt",
                  children: jsx(Card, { embedded: true })
                }),
                jsx("section", {
                  id: skillsPanelId,
                  role: "tabpanel",
                  "aria-labelledby": skillsTabId,
                  hidden: tab !== "skills",
                  children: jsx(SkillLibrary, { active: open && tab === "skills" })
                }),
                jsx("section", {
                  id: campaignPanelId,
                  role: "tabpanel",
                  "aria-labelledby": campaignTabId,
                  hidden: tab !== "campaign",
                  children: jsx(CampaignPanel, { active: open && tab === "campaign", sessionIdHint: (sessionId || "") })
                }),
                jsx("section", {
                  id: knowledgePanelId,
                  role: "tabpanel",
                  "aria-labelledby": knowledgeTabId,
                  hidden: tab !== "knowledge",
                  children: jsx(KnowledgePanel, { active: open && tab === "knowledge" })
                })
              ]
            })
          ]
        })
      });
    }
    function apply(ctx) {
      // Startup disclaimer: once per Harness launch; acceptance dismisses it for this run, refusal closes the app.
      function DisclaimerGate() {
        const KEY = "dsh-prompt-custom-disclaimer-v1";
        const [open, setOpen] = react.useState(() => {
          try { return window.sessionStorage.getItem(KEY) !== "accepted"; } catch (error) { return true; }
        });
        const accept = () => {
          try { window.sessionStorage.setItem(KEY, "accepted"); } catch (error) {}
          setOpen(false);
        };
        const refuse = () => {
          try {
            const request = fetch("/api/dsh-prompt-custom/shutdown", {
              method: "POST",
              headers: { "content-type": "application/json", "x-dsh-ui": "1" },
              body: "{}"
            });
            if (request && typeof request.catch === "function") request.catch(() => {});
          } catch (error) {}
          setTimeout(() => { try { window.close(); } catch (error) {} }, 400);
        };
        const bullet = (text) => jsx("li", { style: { margin: "0 0 6px", lineHeight: "20px" }, children: text });
        const root = jsx("div", {
          style: {
            position: "fixed",
            inset: 0,
            zIndex: 2147483000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "rgba(15, 23, 42, 0.55)",
            pointerEvents: "auto"
          },
          onMouseDown: (event) => { if (event && event.stopPropagation) event.stopPropagation(); },
          onClick: (event) => { if (event && event.stopPropagation) event.stopPropagation(); },
          children: jsx("div", {
            style: {
              width: "min(520px, calc(100vw - 48px))",
              maxHeight: "calc(100vh - 80px)",
              overflow: "auto",
              background: "#fff",
              color: "#1f2328",
              border: "1px solid #d0d7de",
              borderRadius: 12,
              boxShadow: "0 20px 48px rgba(0,0,0,0.28)",
              padding: "20px 22px 16px"
            },
            children: [
              jsx("div", { style: { fontSize: 17, fontWeight: 700, marginBottom: 2 }, children: "Disclaimer and Terms of Use" }),
              jsx("div", { style: { fontSize: 12, color: "#6b7280", marginBottom: 14 }, children: "Fujiang Armor Breaker Plugin · dsh-prompt-custom · v1.1" }),
              jsx("div", { style: { fontSize: 13, lineHeight: "21px" }, children: [

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "1. Authorization Prerequisites" }),
                jsx("div", { style: { margin: "0 0 12px" }, children: "Before using this plugin, confirm that at least one of the following applies:" }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "1) You personally own the target asset;" }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "2) You have written authorization from the target owner, with a defined testing scope and time window;" }),
                jsx("div", { style: { margin: "0 0 12px", paddingLeft: 14 }, children: "3) The target is a public practice range, a CTF competition, or an isolated lab environment you created." }),

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "2. User Responsibilities" }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "1) You must independently confirm each test's target, scope, frequency, and impact, and accept responsibility for them." }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "2) Knowledge base entries and PoCs are for learning, reproduction, and authorized assessments. Their use against unauthorized systems is the user's individual action." }),
                jsx("div", { style: { margin: "0 0 12px", paddingLeft: 14 }, children: "3) You must comply with local laws and regulations and your agreements with the target owner. You personally bear all resulting consequences." }),

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "3. Capabilities and Risks" }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "1) The plugin provides fingerprint matching, PoC references, campaign ledgers, and automatic continuation. The model sends actual packets within your environment." }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "2) Some PoCs are destructive (writing files, restarting services, changing configuration). Validate their effects in a lab first." }),
                jsx("div", { style: { margin: "0 0 12px", paddingLeft: 14 }, children: "3) Automatic continuation advances while the objective remains unmet (default limit: 8 rounds), which may generate additional requests and access logs." }),

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "4. Data and Privacy" }),
                jsx("div", { style: { margin: "0 0 4px", paddingLeft: 14 }, children: "1) Campaign ledgers, vulnerability reports, and installation logs are stored in the local DSH_HOME directory. The plugin operates entirely offline." }),
                jsx("div", { style: { margin: "0 0 12px", paddingLeft: 14 }, children: "2) Store, use, and promptly destroy credentials, personal information, and business data obtained during testing in accordance with your authorization agreement." }),

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "5. Limitation of Liability" }),
                jsx("div", { style: { margin: "0 0 12px" }, children: "To the fullest extent permitted by applicable law, the plugin's authors and distributors disclaim liability for losses arising from its use, including data corruption, business interruption, and compliance liabilities." }),

                jsx("div", { style: { fontWeight: 600, margin: "0 0 4px" }, children: "6. Acknowledgment" }),
                jsx("div", { style: { margin: "0 0 4px" }, children: "Clicking Agree and Comply confirms that you have read, understood, and accepted all terms above for this run." }),
                jsx("div", { style: { margin: "0 0 0" }, children: "Clicking Decline immediately closes DeepSeek Harness. Pressing Enter or Esc also counts as acceptance." })
              ] }),
              jsx("div", { style: { display: "flex", gap: 8, justifyContent: "flex-end" }, children: [
                jsx("button", {
                  type: "button",
                  onClick: refuse,
                  style: {
                    padding: "7px 14px",
                    fontSize: 13,
                    borderRadius: 8,
                    border: "1px solid #d0d7de",
                    background: "#f6f8fa",
                    color: "#b42318",
                    cursor: "pointer"
                  },
                  children: "Decline"
                }),
                jsx("button", {
                  type: "button",
                  onClick: accept,
                  style: {
                    padding: "7px 16px",
                    fontSize: 13,
                    fontWeight: 600,
                    borderRadius: 8,
                    border: "1px solid #169760",
                    background: "#169760",
                    color: "#fff",
                    cursor: "pointer"
                  },
                  children: "Agree and Comply"
                })
              ] })
            ]
          })
        });
        // Keyboard fallback: Enter / Esc equal Agree and Comply, avoiding a dead end if the overlay cannot be clicked.
        react.useEffect(() => {
          if (!open) return;
          const onKey = (event) => {
            if (event && (event.isComposing || event.keyCode === 229)) return;
            const key = event && event.key;
            if (key === "Enter" || key === "Escape") {
              try { event.preventDefault(); event.stopPropagation(); } catch (error) {}
              try { window.sessionStorage.setItem(KEY, "accepted"); } catch (error) {}
              setOpen(false);
            }
          };
          window.addEventListener("keydown", onKey, true);
          return () => { try { window.removeEventListener("keydown", onKey, true); } catch (error) {} };
        }, [open]);
        if (!open) return null;
        // Mount on body to avoid pointer-events / transform restrictions imposed by the slot container.
        try {
          const reactDom = require("react-dom");
          if (reactDom && typeof reactDom.createPortal === "function" && typeof document !== "undefined" && document.body) {
            return reactDom.createPortal(root, document.body);
          }
        } catch (error) {}
        return root;
      }

      function PromptToggle(props) {
        // The slot injects the current session ID; use an empty string if unavailable (the panel falls back to a list).
        const sessionId = props && props.sessionId ? String(props.sessionId) : "";
        const [enabled, setEnabled] = react.useState(false);
        const [phase, setPhase] = react.useState("loading");
        const [busy, setBusy] = react.useState(false);
        const [error, setError] = react.useState("");
        const operation = react.useRef(false);
        const [panelOpen, setPanelOpen] = react.useState(false);
        const panelId = react.useId();

        const refresh = react.useCallback(async () => {
          if (operation.current) return;
          try {
            const resp = await fetch(TOGGLE_URL, { headers: { accept: "application/json" } });
            const data = await resp.json();
            if (!resp.ok || !data || data.ok === false || typeof data.enabled !== "boolean") {
              throw new Error("toggle status unavailable");
            }
            setEnabled(data.enabled);
            setError("");
            setPhase("ready");
          } catch (e) {
            setError(L.toggleError);
            setPhase((current) => current === "ready" ? "ready" : "error");
          }
        }, []);

        react.useEffect(() => {
          refresh();
          window.addEventListener("focus", refresh);
          return () => window.removeEventListener("focus", refresh);
        }, [refresh]);

        const change = async (next) => {
          if (operation.current || phase !== "ready") return;
          operation.current = true;
          setBusy(true);
          setError("");
          try {
            const resp = await fetch(TOGGLE_URL, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ enabled: !!next })
            });
            const data = await resp.json();
            if (!resp.ok || !data || data.ok === false || typeof data.enabled !== "boolean") {
              throw new Error("toggle update failed");
            }
            setEnabled(data.enabled);
          } catch (e) {
            setError(L.toggleError);
          } finally {
            operation.current = false;
            setBusy(false);
          }
        };

        return jsxs("div", {
          "data-prompt-custom-overlay": "",
          onClick: (event) => event.stopPropagation(),
          style: {
            // The official overlay anchor sits at the top of the composer card.
            // Stay outside normal layout so the workspace/preset row keeps its native position.
            position: "absolute",
            left: 0,
            right: 0,
            bottom: 8,
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            height: 28,
            boxSizing: "border-box",
            margin: 0,
            padding: 0,
            pointerEvents: "none"
          },
          children: [
            jsx("style", { children: PANEL_CSS }),
            jsxs("div", {
              style: { position: "relative", display: "inline-flex", height: 28, pointerEvents: "none" },
              children: [
                jsx("button", {
                  type: "button",
                  className: "dsh-fuj-settings-trigger",
                  "data-prompt-custom-settings": "",
                  "aria-label": L.pluginSettings,
                  "aria-haspopup": "dialog",
                  "aria-expanded": panelOpen,
                  "aria-controls": panelOpen ? panelId : undefined,
                  title: L.pluginSettings,
                  onClick: (event) => { event.stopPropagation(); setPanelOpen(true); },
                  children: jsx(IconSettingsOutlineRegular, { size: 16 })
                }),
                jsxs("button", {
            "data-prompt-custom-toggle": "",
            type: "button",
            role: "switch",
            "aria-label": L.toggleLabel,
            "aria-checked": enabled,
            "aria-busy": busy || phase === "loading",
            disabled: busy || phase === "loading",
            title: error ? error + ", click to retry" : (enabled ? "Click to disable " : "Click to enable ") + L.toggleLabel,
            onClick: (event) => {
              event.stopPropagation();
              return error || phase === "error" ? refresh() : change(!enabled);
            },
            style: {
              appearance: "none",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              alignSelf: "flex-start",
              flex: "0 0 auto",
              gap: 7,
              width: "max-content",
              minWidth: 0,
              height: 28,
              minHeight: 28,
              maxHeight: 28,
              boxSizing: "border-box",
              margin: 0,
              padding: "0 10px",
              border: "1px solid " + (error ? "rgba(180, 35, 24, 0.28)" : enabled ? "rgba(22, 151, 96, 0.30)" : "var(--dsw-alias-border-l3, #dfe2e5)"),
              borderRadius: 6,
              background: error ? "rgba(180, 35, 24, 0.06)" : enabled ? "rgba(22, 151, 96, 0.08)" : "var(--dsw-alias-background-secondary, rgba(120, 128, 140, 0.06))",
              boxShadow: "none",
              pointerEvents: "auto",
              fontFamily: "inherit",
              fontSize: 13,
              fontWeight: 500,
              lineHeight: "18px",
              color: "var(--dsw-alias-label-primary, #20252b)",
              whiteSpace: "nowrap",
              cursor: busy || phase === "loading" ? "wait" : "pointer",
              opacity: busy || phase === "loading" ? 0.65 : 1
            },
            children: [
              jsx("span", {
                "aria-hidden": true,
                style: {
                  display: "block",
                  flex: "0 0 6px",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: error ? "#b42318" : enabled ? "#169760" : "#959ca5"
                }
              }),
              jsx("span", {
                style: { display: "block", lineHeight: "18px" },
                children: L.toggleLabel + " · " + (error ? "Retry pending" : phase !== "ready" ? L.toggleLoading : enabled ? L.toggleOn : L.toggleOff)
              })
            ]
                })
              ]
            }),
            jsx(PluginPanel, {
              sessionId,
              id: panelId,
              open: panelOpen,
              onClose: () => { setPanelOpen(false); refresh(); }
            }),
            jsx(DisclaimerGate, {})
          ]
        });
      }

      ctx.slots.inject("conversation.input.overlay", () => ctx.slots.register({
        name: "conversation.input.overlay",
        id: "dsh-prompt-custom-toggle",
        order: 90,
        inject: (sessionId) => ({ sessionId: sessionId === undefined ? "" : String(sessionId) })
      }, PromptToggle));

      // Settings are global: inject only makes a best-effort attempt to get the current session; otherwise use list selection.
      const registerSettings = (withInject) => () => ctx.slots.register({
        name: "settings.section",
        id: "dsh-prompt-custom",
        order: 60,
        label: () => L.nav,
        ...(withInject ? { inject: (sessionId) => ({ sessionId: sessionId === undefined ? "" : String(sessionId) }) } : {})
      }, (props) => jsx(Card, props));
      try {
        ctx.slots.inject("settings.section", registerSettings(true));
      } catch (error) {
        ctx.slots.inject("settings.section", registerSettings(false));
      }
    }

    const inject = ["slots"];
    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  }
});
