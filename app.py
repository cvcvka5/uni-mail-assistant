#!/usr/bin/env python3
"""Uni Mail Assistant – chat window. Answers ONLY from emails really downloaded from your inbox."""
import datetime as dt
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import scrolledtext

import gmail_oauth
import helper

BG, CARD, BLUE, GREY, TEXT = "#F5F5F7", "#FFFFFF", "#0071E3", "#86868B", "#1D1D1F"


def day_start(d):
    return dt.datetime.combine(d, dt.time())


def pick_range(question):
    """Turns the question into an exact time window, so the AI can't 'guess' dates."""
    q = question.lower()
    today = dt.date.today()
    if re.search(r"yesterday|gestern", q):
        return day_start(today - dt.timedelta(days=1)), day_start(today), "yesterday (%s)" % (today - dt.timedelta(days=1)).strftime("%a %d %b")
    if re.search(r"\btoday\b|heute", q):
        return day_start(today), day_start(today + dt.timedelta(days=1)), "today"
    if re.search(r"last week|letzte woche|this week|diese woche|7 days", q):
        return day_start(today - dt.timedelta(days=7)), day_start(today + dt.timedelta(days=1)), "the last 7 days"
    if re.search(r"month|monat|30 days", q):
        return day_start(today - dt.timedelta(days=30)), day_start(today + dt.timedelta(days=1)), "the last 30 days"
    return day_start(today - dt.timedelta(days=14)), day_start(today + dt.timedelta(days=1)), "the last 14 days"


ANSWER_PROMPT = """You are the student's university email assistant. Today is {now}.
Below are the emails from {label} that passed the relevance filter (noise such as security alerts,
receipts, shipping and newsletters is already removed). Each has a number like [#3] and an inbox address.

STRICT RULES:
- Use ONLY these emails. Never invent emails, senders, dates or deadlines.
- Be extremely brief: one short line per email, naming what to do or why it matters. No intro, no outro.
- Things the student must do first (with deadline), then good-to-know.
- If there are several inboxes, group by inbox address as a CAPITAL heading.
- After each point, add the email number, e.g. [#3].
- Plain text only (no markdown symbols). Use "•" for bullets.
- Answer in the language of the question.

Question: {question}

EMAILS ({count}):
{emails}

Dates already waiting for confirmation / in calendar:
{items}"""


def answer(question):
    con = helper.db()
    start, end, label = pick_range(question)
    rows = con.execute("SELECT * FROM emails WHERE received>=? AND received<? AND " + helper.SIGNAL +
                       " ORDER BY account, received", (start.isoformat(), end.isoformat())).fetchall()
    last = helper.get_state(con, "last_sync") or "never"
    if not rows:
        return ("Nothing needs your attention for %s.\n(Last check of your mailbox: %s. "
                "Press 'Sync emails' to check now.)" % (label, last))
    lines = []
    for i, r in enumerate(rows, 1):
        lines.append("[#%d] inbox: %s | %s | from: %s <%s> | subject: %s | importance: %s | category: %s\n     summary: %s%s%s" % (
            i, r["account"], r["received"].replace("T", " "), r["sender"], r["sender_addr"], r["subject"],
            r["importance"], r["category"] or "-",
            (r["summary"] or "").replace(" || ", ": ") or (r["body"] or "")[:300],
            ("\n     to do: " + r["action"]) if r["action"] else "",
            "\n     needs a reply (not replied yet)" if r["needs_reply"] and not r["replied"] else ""))
    items = con.execute("SELECT kind,title,day,time,status FROM items WHERE day>=? AND status IN ('pending','added') ORDER BY day",
                        (dt.date.today().isoformat(),)).fetchall()
    items_txt = "\n".join("- %s: %s on %s (%s)" % (i["kind"], i["title"], helper.pretty(i["day"], i["time"]),
                          "waiting for you to confirm" if i["status"] == "pending" else "in calendar") for i in items) or "none"
    text = helper.gemini(ANSWER_PROMPT.format(now=dt.datetime.now().strftime("%A %Y-%m-%d %H:%M"), label=label,
                                              question=question, count=len(rows), emails="\n".join(lines),
                                              items=items_txt), want_json=False)
    text = re.sub(r"\*\*|__|^#+\s*", "", text, flags=re.M)
    sources = "\n".join("  #%d  %s  [%s] %s – %s" % (i, r["received"][5:16].replace("T", " "), r["account"], r["sender"][:28], r["subject"][:60])
                        for i, r in enumerate(rows, 1))
    return "%s\n\n— %d relevant email(s) from %s (last mailbox check: %s):\n%s" % (
        text, len(rows), label, last.replace("T", " "), sources)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Uni Mail Assistant")
        self.geometry("860x680")
        self.configure(bg=BG)
        tk.Label(self, text="🎓 Uni Mail Assistant", font=("Helvetica Neue", 20, "bold"), bg=BG, fg=TEXT).pack(anchor="w", padx=16, pady=(14, 0))
        self.status = tk.Label(self, text="", font=("Helvetica Neue", 12), bg=BG, fg=GREY)
        self.status.pack(anchor="w", padx=16)
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=12, pady=8)
        for label, q in [("📅 Yesterday", "What emails did I receive yesterday? Summarize all of them."),
                         ("📊 Last week", "Summarize last week's emails. What do I need to do?"),
                         ("⚠️ To do & deadlines", "What must I do and what are my upcoming deadlines? (last 30 days)")]:
            tk.Button(bar, text=label, command=lambda q=q: self.ask(q), font=("Helvetica Neue", 13)).pack(side="left", padx=4)
        tk.Button(bar, text="🔄 Sync emails", command=self.sync, font=("Helvetica Neue", 13)).pack(side="left", padx=4)
        tk.Button(bar, text="📬 Gmail accounts", command=self.manage_accounts, font=("Helvetica Neue", 13)).pack(side="left", padx=4)
        self.out = scrolledtext.ScrolledText(self, wrap="word", font=("Helvetica Neue", 14), bg=CARD, fg=TEXT,
                                             relief="flat", padx=12, pady=10)
        self.out.pack(fill="both", expand=True, padx=16)
        self.out.tag_config("you", foreground=BLUE, font=("Helvetica Neue", 14, "bold"))
        self.out.tag_config("note", foreground=GREY)
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=16, pady=12)
        self.entry = tk.Entry(row, font=("Helvetica Neue", 14))
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.entry.bind("<Return>", lambda e: self.ask(self.entry.get()))
        tk.Button(row, text="Ask", command=lambda: self.ask(self.entry.get()), font=("Helvetica Neue", 13)).pack(side="left", padx=6)
        self.refresh_status()

    def refresh_status(self):
        con = helper.db()
        last = helper.get_state(con, "last_sync")
        n = con.execute("SELECT COUNT(*) FROM emails WHERE " + helper.SIGNAL).fetchone()[0]
        g = len(helper.gmail_accounts(con))
        self.status.config(text="%d relevant emails · %d Gmail account(s) · last mailbox check: %s" % (
            n, g, (last or "never").replace("T", " ")))

    def write(self, text, tag=None):
        self.out.insert("end", text, tag)
        self.out.see("end")

    def ask(self, q):
        q = q.strip()
        if not q:
            return
        self.entry.delete(0, "end")
        self.write("\nYou: ", "you")
        self.write(q + "\n")
        self.write("Reading your emails…\n", "note")
        def work():
            try:
                res = answer(q)
            except Exception as e:
                res = "Problem: %s" % e
            self.after(0, lambda: self.write(res + "\n"))
        threading.Thread(target=work, daemon=True).start()

    def manage_accounts(self):
        win = tk.Toplevel(self)
        win.title("Gmail accounts")
        win.geometry("460x320")
        win.configure(bg=BG)
        box = tk.Frame(win, bg=BG)
        box.pack(fill="both", expand=True, padx=16, pady=12)
        msg = tk.Label(win, text="", bg=BG, fg=GREY, wraplength=420, justify="left")

        def render():
            for w in box.winfo_children():
                w.destroy()
            rows = gmail_oauth.accounts()
            if not rows:
                tk.Label(box, text="No Gmail accounts linked yet.", bg=BG, fg=GREY).pack(anchor="w")
            for r in rows:
                line = tk.Frame(box, bg=BG)
                line.pack(fill="x", pady=3)
                tk.Label(line, text=r["email"], bg=BG, fg=TEXT, font=("Helvetica Neue", 13)).pack(side="left")
                tk.Button(line, text="Disconnect", command=lambda a=r["email"]: disconnect(a)).pack(side="right")

        def disconnect(addr):
            try:
                gmail_oauth.remove(addr)
                msg.config(text="Disconnected %s (token revoked, stored mail wiped)." % addr)
            except Exception as e:
                msg.config(text="Problem: %s" % e)
            render()
            self.refresh_status()

        def add(client_id):
            msg.config(text="Complete the sign-in in your browser…")

            def work():
                try:
                    text = "Linked %s." % gmail_oauth.link(client_id)
                except Exception as e:
                    text = "Problem: %s" % e
                self.after(0, lambda: (msg.config(text=text), render(), self.refresh_status()))
            threading.Thread(target=work, daemon=True).start()

        for c in gmail_oauth.clients() or [{"client_id": None}]:
            label = "➕ Link a Gmail account" + (" (client …%s)" % c["client_id"][:12] if len(gmail_oauth.clients()) > 1 else "")
            tk.Button(win, text=label, command=lambda cid=c["client_id"]: add(cid), font=("Helvetica Neue", 13)).pack(pady=4)
        msg.pack(padx=16, pady=(0, 10), anchor="w")
        render()

    def sync(self):
        self.write("\nChecking your mailbox…\n", "note")
        def work():
            r = subprocess.run([sys.executable, helper.__file__, "sync"], capture_output=True, text=True)
            msg = (r.stdout.strip().splitlines() or ["done"])[-1]
            self.after(0, lambda: (self.write(msg + "\n", "note"), self.refresh_status()))
        threading.Thread(target=work, daemon=True).start()


if __name__ == "__main__":
    App().mainloop()
