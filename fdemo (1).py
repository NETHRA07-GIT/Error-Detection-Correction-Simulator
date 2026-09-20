"""
Error Detection & Correction Simulator
Networks Project — Python Tkinter
Techniques: VRC, LRC, CRC, Checksum, Hamming Code
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import math

# ══════════════════════════════════════════════════
#  COLOUR PALETTE
# ══════════════════════════════════════════════════
BG       = "#F0F4F8"
SIDEBAR  = "#1E2D3D"
CARD     = "#FFFFFF"
ACCENT   = "#00B4A6"
TEXT_D   = "#1E2D3D"
TEXT_L   = "#FFFFFF"
MUTED    = "#8A9BB0"
BORDER   = "#D6E0EA"
GOLD     = "#B07D00"
MONO     = ("Consolas", 10)
MONO_BIG = ("Consolas", 11)
LABEL_F  = ("Segoe UI", 10)
BTN_F    = ("Segoe UI", 10, "bold")
SMALL_F  = ("Segoe UI", 9)


# ══════════════════════════════════════════════════
#  ALGORITHMS
# ══════════════════════════════════════════════════

# ── VRC ──────────────────────────────────────────
def vrc_encode(data, parity="even"):
    bits = [int(b) for b in data]
    ones = sum(bits)
    p = (0 if ones % 2 == 0 else 1) if parity == "even" else (1 if ones % 2 == 0 else 0)
    codeword = data + str(p)
    lines = [
        f"  Data bits       :  {data}",
        f"  Count of 1s     :  {ones}",
        f"  Parity type     :  {parity.upper()}",
        f"  Parity bit      :  {p}",
        f"  Codeword sent   :  {codeword}",
    ]
    return codeword, lines

def vrc_verify(received, parity="even"):
    bits = [int(b) for b in received]
    ones = sum(bits)
    ok = (ones % 2 == 0) if parity == "even" else (ones % 2 != 0)
    lines = [
        f"  Received        :  {received}",
        f"  Count of 1s     :  {ones}",
        f"  Parity type     :  {parity.upper()}",
        f"  Check           :  {ones} is {'EVEN' if ones%2==0 else 'ODD'}",
        f"  Result          :  {'No error detected' if ok else 'ERROR DETECTED!'}",
    ]
    return ok, lines


# ── LRC ──────────────────────────────────────────
def lrc_encode(bytes_list):
    length = len(bytes_list[0])
    lrc = [0] * length
    lines = ["  Input bytes:"]
    for i, byte in enumerate(bytes_list):
        lines.append(f"      Byte {i+1}  ->  {byte}")
        for j in range(length):
            lrc[j] ^= int(byte[j])
    lrc_str = ''.join(map(str, lrc))
    lines.append(f"      {'─'*24}")
    lines.append(f"  LRC byte        :  {lrc_str}")
    lines.append(f"  Transmitted     :  {' '.join(bytes_list)}  {lrc_str}")
    return lrc_str, lines

def lrc_verify(bytes_list):
    """bytes_list includes the LRC byte as the last element."""
    length = len(bytes_list[0])
    result = [0] * length
    lines = ["  Received bytes (last = LRC):"]
    for i, byte in enumerate(bytes_list):
        label = "  (LRC)" if i == len(bytes_list)-1 else "       "
        lines.append(f"      Byte {i+1} {label}  ->  {byte}")
        for j in range(length):
            result[j] ^= int(byte[j])
    result_str = ''.join(map(str, result))
    ok = all(r == 0 for r in result)
    lines.append(f"      {'─'*24}")
    lines.append(f"  XOR result      :  {result_str}")
    lines.append(f"  Expected        :  {'0'*length}  (all zeros)")
    lines.append(f"  Result          :  {'No error detected' if ok else 'ERROR DETECTED!'}")
    return ok, lines


# ── CRC ──────────────────────────────────────────
def _xor_div(dividend, divisor):
    d = list(dividend)
    n = len(divisor)
    for i in range(len(d) - n + 1):
        if d[i] == 1:
            for j in range(n):
                d[i+j] ^= divisor[j]
    return d[-(n-1):]

def crc_encode(data, gen):
    data_bits = [int(b) for b in data]
    gen_bits  = [int(b) for b in gen]
    deg = len(gen_bits) - 1
    padded = data_bits + [0]*deg
    rem = _xor_div(padded, gen_bits)
    rem_str = ''.join(map(str, rem))
    codeword = data + rem_str
    lines = [
        f"  Data            :  {data}",
        f"  Generator       :  {gen}  (degree {deg})",
        f"  After padding   :  {''.join(map(str,padded))}",
        f"  CRC remainder   :  {rem_str}",
        f"  Codeword sent   :  {codeword}",
    ]
    return codeword, lines

def crc_verify(received, gen):
    recv_bits = [int(b) for b in received]
    gen_bits  = [int(b) for b in gen]
    rem = _xor_div(recv_bits, gen_bits)
    rem_str = ''.join(map(str, rem))
    ok = all(r == 0 for r in rem)
    lines = [
        f"  Received        :  {received}",
        f"  Generator       :  {gen}",
        f"  Remainder       :  {rem_str}",
        f"  Result          :  {'No error (remainder=0)' if ok else 'ERROR DETECTED! (remainder!=0)'}",
    ]
    return ok, lines


# ── CHECKSUM ─────────────────────────────────────
def _oc_add(a, b, bits):
    s = a + b
    while s >= (1 << bits):
        s = (s & ((1 << bits)-1)) + (s >> bits)
    return s

def checksum_encode(data, ws=8):
    bits = data.replace(" ", "")
    if len(bits) % ws:
        bits += '0' * (ws - len(bits) % ws)
    words = [bits[i:i+ws] for i in range(0, len(bits), ws)]
    total = 0
    lines = [f"  Data (padded)   :  {bits}", f"  Word size       :  {ws} bits", "  Words:"]
    for i, w in enumerate(words):
        v = int(w, 2)
        total = _oc_add(total, v, ws)
        lines.append(f"      Word {i+1}  ->  {w}  (={v})")
    sum_str = format(total, f'0{ws}b')
    ck = ''.join('1' if b=='0' else '0' for b in sum_str)
    lines.append(f"  Running sum     :  {sum_str}  (={total})")
    lines.append(f"  Checksum (1's complement)  :  {ck}")
    lines.append(f"  Transmitted     :  {bits}  {ck}")
    return ck, lines

def checksum_verify(data, ws=8):
    bits = data.replace(" ", "")
    if len(bits) % ws != 0:
        return None, [f"  Data length must be divisible by {ws}."]
    words = [bits[i:i+ws] for i in range(0, len(bits), ws)]
    total = 0
    lines = ["  Received words (last = checksum):"]
    for i, w in enumerate(words):
        v = int(w, 2)
        total = _oc_add(total, v, ws)
        label = "  (checksum)" if i==len(words)-1 else "            "
        lines.append(f"      Word {i+1} {label}  ->  {w}")
    sum_str = format(total, f'0{ws}b')
    ok = (sum_str == '1'*ws)
    lines.append(f"  Final sum       :  {sum_str}")
    lines.append(f"  Expected        :  {'1'*ws}  (all 1s)")
    lines.append(f"  Result          :  {'No error detected' if ok else 'ERROR DETECTED!'}")
    return ok, lines


# ── HAMMING ──────────────────────────────────────
def hamming_encode(data):
    m = len(data)
    r = 0
    while (1 << r) < m + r + 1:
        r += 1
    n = m + r
    cw = ['0'] * (n + 1)
    data_positions = []
    di = 0
    for i in range(1, n+1):
        if (i & (i-1)) != 0:
            cw[i] = data[di]; data_positions.append(i); di += 1
    parity_positions = []
    for p in range(r):
        pos = 1 << p; parity_positions.append(pos)
        xval = 0
        for i in range(1, n+1):
            if i != pos and (i & pos):
                xval ^= int(cw[i])
        cw[pos] = str(xval)
    codeword = ''.join(cw[1:])
    lines = [
        f"  Data bits       :  {data}  (m={m})",
        f"  Parity bits     :  {r}  (since 2^{r}={1<<r} >= {m+r+1})",
        f"  Total length    :  {n} bits",
        f"  Parity pos      :  {parity_positions}",
        f"  Data pos        :  {data_positions}",
        "",
        "  Parity bit values:"
    ]
    for p in range(r):
        pos = 1 << p
        covered = [i for i in range(1, n+1) if (i & pos)]
        vals = [cw[i] for i in covered]
        lines.append(f"      P{pos}  covers {covered}  ->  XOR({','.join(vals)}) = {cw[pos]}")
    lines.append("")
    pos_row = "  ".join([f"[{i}]" for i in range(1, n+1)])
    val_row = "    ".join([f"{cw[i]}" for i in range(1, n+1)])
    lines.append(f"  Position layout:")
    lines.append(f"      {pos_row}")
    lines.append(f"      {val_row}")
    lines.append("")
    lines.append(f"  Codeword sent   :  {codeword}")
    return codeword, lines

def hamming_decode(received):
    n = len(received)
    cw = ['0'] + list(received)
    r = 0
    while (1 << r) <= n:
        r += 1
    r -= 1
    syndrome = 0
    lines = [f"  Received        :  {received}  (length {n})", f"  Parity bits     :  {r}", "", "  Syndrome:"]
    for p in range(r):
        pos = 1 << p
        covered = [i for i in range(1, n+1) if (i & pos)]
        xval = 0
        for i in covered:
            xval ^= int(cw[i])
        syndrome |= (xval << p)
        status = "FAIL" if xval else "OK"
        lines.append(f"      C{pos}  covers {covered}  ->  {xval}  [{status}]")
    syndrome_bin = format(syndrome, f'0{r}b')
    lines.append("")
    lines.append(f"  Syndrome        :  {syndrome_bin} = {syndrome} (decimal)")
    if syndrome == 0:
        lines.append("  No error detected.")
        data = ''.join(cw[i] for i in range(1, n+1) if (i & (i-1)) != 0)
        lines.append(f"  Extracted data  :  {data}")
        return data, lines, False
    else:
        lines.append(f"  ERROR at position {syndrome}!")
        if 1 <= syndrome <= n:
            orig = cw[syndrome]
            cw[syndrome] = '1' if orig=='0' else '0'
            lines.append(f"  Correcting pos {syndrome}: {orig} -> {cw[syndrome]}")
        lines.append(f"  Corrected cw    :  {''.join(cw[1:])}")
        data = ''.join(cw[i] for i in range(1, n+1) if (i & (i-1)) != 0)
        lines.append(f"  Extracted data  :  {data}")
        return data, lines, True


# ══════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════
def is_binary(s):
    return len(s) > 0 and all(c in '01' for c in s)

def parse_bytes(raw):
    parts = raw.strip().split()
    if len(parts) < 2:
        return None, "Enter at least 2 bytes separated by spaces."
    L = len(parts[0])
    for p in parts:
        if len(p) != L:
            return None, f"All bytes must be the same length (expected {L})."
        if not is_binary(p):
            return None, f"'{p}' is not binary."
    return parts, None


# ══════════════════════════════════════════════════
#  GUI APPLICATION
# ══════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Error Detection & Correction Simulator")
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.configure(bg=BG)
        self._build()

    def _build(self):
        self._sidebar()
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(side="left", fill="both", expand=True)
        self._show("vrc")

    # ─── SIDEBAR ─────────────────────────────────
    def _sidebar(self):
        sb = tk.Frame(self, bg=SIDEBAR, width=230)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)
        # logo
        tk.Frame(sb, bg=SIDEBAR, height=10).pack()
        tk.Label(sb, text="⬡  NetSim", font=("Georgia", 16, "bold"),
                 fg=ACCENT, bg=SIDEBAR).pack(pady=(18,2))
        tk.Label(sb, text="Error Detection & Correction", font=("Segoe UI", 8),
                 fg=MUTED, bg=SIDEBAR, wraplength=180).pack()
        tk.Frame(sb, bg="#2E4057", height=1).pack(fill="x", padx=20, pady=14)

        tk.Label(sb, text="  DETECTION", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SIDEBAR, anchor="w").pack(fill="x", padx=18, pady=(0,4))
        self._btns = {}
        for key, label, desc in [
            ("vrc",      "VRC",      "Vertical Redundancy Check"),
            ("lrc",      "LRC",      "Longitudinal Redundancy Check"),
            ("crc",      "CRC",      "Cyclic Redundancy Check"),
            ("checksum", "Checksum", "Internet Checksum"),
        ]:
            self._nav(sb, key, label, desc)

        tk.Frame(sb, bg="#2E4057", height=1).pack(fill="x", padx=20, pady=12)
        tk.Label(sb, text="  CORRECTION", font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=SIDEBAR, anchor="w").pack(fill="x", padx=18, pady=(0,4))
        self._nav(sb, "hamming", "Hamming", "Error Correction Code")

        tk.Frame(sb, bg="#2E4057", height=1).pack(fill="x", padx=20, pady=12)
        tk.Label(sb, text="Networks Project", font=("Segoe UI", 8),
                 fg=MUTED, bg=SIDEBAR).pack()

    def _nav(self, parent, key, label, desc):
        f = tk.Frame(parent, bg=SIDEBAR, cursor="hand2")
        f.pack(fill="x", padx=10, pady=2)
        dot  = tk.Label(f, text="●", font=("Segoe UI", 8), fg=MUTED, bg=SIDEBAR, width=2)
        dot.pack(side="left")
        inn  = tk.Frame(f, bg=SIDEBAR)
        inn.pack(side="left")
        nl   = tk.Label(inn, text=label, font=("Segoe UI", 10, "bold"), fg=TEXT_L, bg=SIDEBAR, anchor="w")
        nl.pack(anchor="w")
        dl   = tk.Label(inn, text=desc,  font=("Segoe UI", 8),           fg=MUTED,  bg=SIDEBAR, anchor="w")
        dl.pack(anchor="w")
        def click(e=None, k=key):
            self._show(k)
        for w in (f, dot, inn, nl, dl):
            w.bind("<Button-1>", click)
        self._btns[key] = (f, dot, nl, dl)

    def _highlight(self, active):
        for k, (f, d, nl, dl) in self._btns.items():
            if k == active:
                for w in (f, d, nl, dl): w.config(bg="#253E52")
                d.config(fg=ACCENT); nl.config(fg=ACCENT); dl.config(fg="#7EC8C8")
            else:
                for w in (f, d, nl, dl): w.config(bg=SIDEBAR)
                d.config(fg=MUTED);  nl.config(fg=TEXT_L);  dl.config(fg=MUTED)

    def _show(self, key):
        for w in self._content.winfo_children():
            w.destroy()
        self._highlight(key)
        {"vrc": self._vrc, "lrc": self._lrc, "crc": self._crc,
         "checksum": self._checksum, "hamming": self._hamming}[key]()

    # ─── LAYOUT HELPERS ──────────────────────────
    def _header(self, title, sub, color=ACCENT):
        h = tk.Frame(self._content, bg=color, padx=28, pady=16)
        h.pack(fill="x")
        tk.Label(h, text=title, font=("Georgia", 17, "bold"), fg="white", bg=color).pack(anchor="w")
        tk.Label(h, text=sub,   font=("Segoe UI", 9),          fg="white", bg=color).pack(anchor="w")

    def _scroll_body(self):
        canvas = tk.Canvas(self._content, bg=BG, bd=0, highlightthickness=0)
        vsb = tk.Scrollbar(self._content, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=BG)
        bid  = canvas.create_window((0,0), window=body, anchor="nw")
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(bid, width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        tk.Frame(body, bg=BG, height=14).pack()
        return body

    def _card(self, body, title):
        outer = tk.Frame(body, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        outer.pack(fill="x", padx=22, pady=(0,12))
        tk.Label(outer, text=title, font=("Segoe UI", 9, "bold"),
                 fg=MUTED, bg=CARD, padx=14, pady=8).pack(anchor="w")
        tk.Frame(outer, bg=BORDER, height=1).pack(fill="x")
        inner = tk.Frame(outer, bg=CARD, padx=14, pady=12)
        inner.pack(fill="x")
        return inner

    def _row(self, parent, label, entry_width=28, hint=""):
        r = tk.Frame(parent, bg=CARD); r.pack(fill="x", pady=3)
        tk.Label(r, text=label, font=LABEL_F, fg=TEXT_D, bg=CARD, width=20, anchor="w").pack(side="left")
        var = tk.StringVar()
        tk.Entry(r, textvariable=var, font=MONO, bg=BG, fg=TEXT_D,
                 insertbackground=ACCENT, bd=1, relief="solid", width=entry_width).pack(side="left", padx=6)
        if hint:
            tk.Label(r, text=hint, font=SMALL_F, fg=MUTED, bg=CARD).pack(side="left")
        return var

    def _radios(self, parent, label, var, options):
        r = tk.Frame(parent, bg=CARD); r.pack(fill="x", pady=3)
        tk.Label(r, text=label, font=LABEL_F, fg=TEXT_D, bg=CARD, width=20, anchor="w").pack(side="left")
        for text, val in options:
            tk.Radiobutton(r, text=text, variable=var, value=val,
                           font=LABEL_F, fg=TEXT_D, bg=CARD, selectcolor=BG,
                           activebackground=CARD, cursor="hand2").pack(side="left", padx=6)

    def _run_button(self, parent, cmd):
        tk.Button(parent, text="▶  Run Simulation", command=cmd,
                  font=BTN_F, fg="white", bg=ACCENT, relief="flat", bd=0,
                  cursor="hand2", padx=20, pady=8,
                  activebackground="#009688", activeforeground="white").pack(anchor="w", pady=(8,2))

    def _out_box(self, body):
        outer = tk.Frame(body, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        outer.pack(fill="both", expand=True, padx=22, pady=(0,18))
        tk.Label(outer, text="OUTPUT", font=("Segoe UI", 9, "bold"),
                 fg=MUTED, bg=CARD, padx=14, pady=8).pack(anchor="w")
        tk.Frame(outer, bg=BORDER, height=1).pack(fill="x")
        out = scrolledtext.ScrolledText(outer, font=MONO_BIG, bg="#FAFCFF", fg=TEXT_D,
                                        bd=0, relief="flat", wrap="word",
                                        state="disabled", padx=14, pady=12, height=14)
        out.pack(fill="both", expand=True)
        out.tag_config("title", foreground="#1E2D3D", font=("Consolas", 12, "bold"))
        out.tag_config("ok",    foreground="#00695C", font=("Consolas", 11, "bold"))
        out.tag_config("err",   foreground="#B71C1C", font=("Consolas", 11, "bold"))
        out.tag_config("gold",  foreground=GOLD,      font=("Consolas", 11, "bold"))
        out.tag_config("step",  foreground="#1E2D3D")
        return out

    def _write(self, out, items):
        out.config(state="normal")
        out.delete("1.0", "end")
        for text, tag in items:
            out.insert("end", text + "\n", tag)
        out.config(state="disabled")

    # ─── VRC PAGE ────────────────────────────────
    def _vrc(self):
        self._header("VRC — Vertical Redundancy Check",
                     "Single parity bit per byte  •  Detects odd-number of bit errors")
        body = self._scroll_body()
        sec  = self._card(body, "CONFIGURATION & INPUT")

        data_var   = self._row(sec, "Data bits", 26, "e.g. 1011010")
        parity_var = tk.StringVar(value="even")
        self._radios(sec, "Parity type", parity_var, [("Even", "even"), ("Odd", "odd")])
        op_var = tk.StringVar(value="encode")
        self._radios(sec, "Operation", op_var,
                     [("Encode (add parity bit)", "encode"),
                      ("Verify (check received)", "verify")])
        tk.Label(sec, text="  Verify: enter data + parity bit, e.g. 10110101",
                 font=SMALL_F, fg=MUTED, bg=CARD).pack(anchor="w")

        out = self._out_box(body)

        def run():
            raw = data_var.get().strip().replace(" ", "")
            if not is_binary(raw):
                messagebox.showwarning("Input Error", "Enter binary (0s and 1s only)."); return
            if op_var.get() == "encode":
                cw, lines = vrc_encode(raw, parity_var.get())
                items = [("  VRC ENCODE", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"), (f"  ✅ Codeword  :  {cw}", "ok")]
            else:
                ok, lines = vrc_verify(raw, parity_var.get())
                items = [("  VRC VERIFY", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"),
                          ("  ✅ DATA IS CORRECT — No error detected!" if ok
                           else "  ❌ ERROR DETECTED in received data!", "ok" if ok else "err")]
            self._write(out, items)
        self._run_button(sec, run)

    # ─── LRC PAGE ────────────────────────────────
    def _lrc(self):
        self._header("LRC — Longitudinal Redundancy Check",
                     "2D block parity  •  Column-wise XOR  •  Better burst error detection",
                     color="#2E7D8C")
        body = self._scroll_body()
        sec  = self._card(body, "CONFIGURATION & INPUT")

        tk.Label(sec, text="Data bytes", font=LABEL_F, fg=TEXT_D, bg=CARD).pack(anchor="w")
        tk.Label(sec,
                 text="  Enter bytes separated by spaces. All bytes must have the same number of bits.\n"
                      "  Encode example :  10110010 01101101 11001100\n"
                      "  Verify example :  10110010 01101101 11001100 00110110   (last = LRC byte)",
                 font=SMALL_F, fg=MUTED, bg=CARD).pack(anchor="w", pady=(0,4))

        data_txt = tk.Text(sec, font=MONO, bg=BG, fg=TEXT_D,
                           insertbackground=ACCENT, bd=1, relief="solid",
                           height=3, width=58, wrap="word")
        data_txt.pack(anchor="w", pady=(0,6))

        op_var = tk.StringVar(value="encode")
        self._radios(sec, "Operation", op_var,
                     [("Encode (compute LRC byte)", "encode"),
                      ("Verify (last byte = LRC)", "verify")])

        out = self._out_box(body)

        def run():
            raw = data_txt.get("1.0", "end").strip()
            bl, err = parse_bytes(raw)
            if err:
                messagebox.showwarning("Input Error", err); return
            if op_var.get() == "encode":
                lrc_str, lines = lrc_encode(bl)
                items = [("  LRC ENCODE", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"),
                          (f"  ✅ LRC byte     :  {lrc_str}", "ok"),
                          (f"  📤 Send block   :  {' '.join(bl)}  {lrc_str}", "gold")]
            else:
                if len(bl) < 3:
                    messagebox.showwarning("Input Error",
                        "Verify needs at least 2 data bytes + 1 LRC byte (3 bytes total)."); return
                ok, lines = lrc_verify(bl)
                items = [("  LRC VERIFY", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"),
                          ("  ✅ DATA IS CORRECT — XOR result is all zeros!" if ok
                           else "  ❌ ERROR DETECTED — XOR result is not all zeros!", "ok" if ok else "err")]
            self._write(out, items)
        self._run_button(sec, run)

    # ─── CRC PAGE ────────────────────────────────
    def _crc(self):
        self._header("CRC — Cyclic Redundancy Check",
                     "Polynomial division  •  Detects burst errors  •  Used in Ethernet, USB, ZIP",
                     color="#5B4B8A")
        body = self._scroll_body()
        sec  = self._card(body, "CONFIGURATION & INPUT")

        data_var = self._row(sec, "Data bits", 30, "e.g. 1101011011")
        gen_var  = self._row(sec, "Generator (binary)", 20, "e.g. 10011")
        gen_var.set("1101")

        pr = tk.Frame(sec, bg=CARD); pr.pack(anchor="w", pady=2)
        tk.Label(pr, text="Presets:", font=SMALL_F, fg=MUTED, bg=CARD).pack(side="left")
        for lbl, v in [("CRC-3 (1101)", "1101"), ("CRC-4 (10011)", "10011"), ("CRC-8 (100000111)", "100000111")]:
            tk.Button(pr, text=lbl, font=SMALL_F, fg=ACCENT, bg=BG, relief="flat",
                      cursor="hand2", bd=1, command=lambda x=v: gen_var.set(x)).pack(side="left", padx=3)

        op_var = tk.StringVar(value="encode")
        self._radios(sec, "Operation", op_var,
                     [("Encode (compute CRC)", "encode"),
                      ("Verify (full codeword)", "verify")])
        tk.Label(sec, text="  Verify: paste the full codeword (data + CRC) from the encode output.",
                 font=SMALL_F, fg=MUTED, bg=CARD).pack(anchor="w")

        out = self._out_box(body)

        def run():
            data = data_var.get().strip().replace(" ", "")
            gen  = gen_var.get().strip().replace(" ", "")
            if not is_binary(data):
                messagebox.showwarning("Input Error", "Data must be binary."); return
            if not is_binary(gen) or len(gen) < 2:
                messagebox.showwarning("Input Error", "Generator must be binary with >=2 bits."); return
            if len(data) < len(gen)-1:
                messagebox.showwarning("Input Error", "Data must be longer than (generator-1)."); return
            if op_var.get() == "encode":
                cw, lines = crc_encode(data, gen)
                items = [("  CRC ENCODE", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"), (f"  ✅ Codeword  :  {cw}", "ok")]
            else:
                ok, lines = crc_verify(data, gen)
                items = [("  CRC VERIFY", "title"), ("", "step")]
                items += [(l, "step") for l in lines]
                items += [("", "step"),
                          ("  ✅ DATA IS CORRECT — Remainder is zero!" if ok
                           else "  ❌ ERROR DETECTED — Non-zero remainder!", "ok" if ok else "err")]
            self._write(out, items)
        self._run_button(sec, run)

    # ─── CHECKSUM PAGE ───────────────────────────
    def _checksum(self):
        self._header("Checksum — Internet Checksum",
                    "1's complement addition  •  Used in TCP / UDP / IP headers",
                    color="#C0392B")
        body = self._scroll_body()
        sec  = self._card(body, "CONFIGURATION & INPUT")

        data_var = self._row(sec, "Data bits (binary)", 34, "e.g. 1010100100000000")

        ws_var   = tk.StringVar(value="8")

        # ✅ 4-bit ADDED HERE
        self._radios(sec, "Word size", ws_var,
                    [("4-bit", "4"), ("8-bit", "8"), ("16-bit", "16")])

        op_var = tk.StringVar(value="encode")
        self._radios(sec, "Operation", op_var,
                    [("Compute checksum", "encode"),
                    ("Verify checksum", "verify")])

        tk.Label(sec,
                text="  Verify: append the checksum bits to data (total length divisible by word size).",
                font=SMALL_F, fg=MUTED, bg=CARD).pack(anchor="w")

        out = self._out_box(body)

        def run():
            data = data_var.get().strip().replace(" ", "")
            ws   = int(ws_var.get())

            if not is_binary(data):
                messagebox.showwarning("Input Error", "Data must be binary.")
                return

            if op_var.get() == "encode":
                ck, lines = checksum_encode(data, ws)

                items = [(f"  CHECKSUM COMPUTE [{ws}-bit]", "title"), ("", "step")]
                items += [(l, "step") for l in lines]

                items += [
                    ("", "step"),
                    (f"  ✅ FINAL CHECKSUM  :  {ck}", "ok")
                ]

            else:
                ok, lines = checksum_verify(data, ws)

                if ok is None:
                    self._write(out, [(lines[0], "err")])
                    return

                items = [(f"  CHECKSUM VERIFY [{ws}-bit]", "title"), ("", "step")]
                items += [(l, "step") for l in lines]

                items += [
                    ("", "step"),
                    ("  ✅ DATA IS CORRECT — Sum is all 1s!" if ok
                    else "  ❌ ERROR DETECTED — Sum is not all 1s!",
                    "ok" if ok else "err")
                ]

            self._write(out, items)

        self._run_button(sec, run)

    # ─── HAMMING PAGE ────────────────────────────
    def _hamming(self):
        self._header("Hamming Code — Error Correction",
                 "Detect & correct single-bit errors  •  Used in ECC RAM, satellites",
                 color="#1B5E20")

        body = self._scroll_body()
        sec  = self._card(body, "CONFIGURATION & INPUT")

        data_var = self._row(sec, "Input bits", 26, "e.g. 1011  (data bits)")

        op_var = tk.StringVar(value="encode")
        self._radios(sec, "Operation", op_var,
                    [("Encode (add Hamming parity bits)", "encode"),
                    ("Decode (detect & correct error)", "decode")])

        tk.Label(sec,
                text="  Decode: enter full Hamming codeword. Flip a bit to simulate an error.",
                font=SMALL_F, fg=MUTED, bg=CARD).pack(anchor="w")

        out = self._out_box(body)

        def run():
            raw = data_var.get().strip().replace(" ", "")

            if not is_binary(raw):
                messagebox.showwarning("Input Error", "Binary bits only.")
                return

            if op_var.get() == "encode":
                cw, lines = hamming_encode(raw)

                items = [("  HAMMING ENCODE", "title"), ("", "step")]
                items += [(l, "step") for l in lines]

                items += [
                    ("", "step"),
                    ("  ─────────────────────────────", "step"),
                    (f"  ✅ FINAL HAMMING CODEWORD  :  {cw}", "ok")
                ]

            else:
                data, lines, corrected = hamming_decode(raw)

                items = [("  HAMMING DECODE & CORRECT", "title"), ("", "step")]
                items += [(l, "step") for l in lines]

                items += [("", "step"), ("  ─────────────────────────────", "step")]

                if corrected:
                    items.append(("  🔧 ERROR CORRECTED SUCCESSFULLY!", "gold"))
                    items.append((f"  ✅ FINAL RECOVERED DATA  :  {data}", "ok"))
                else:
                    items.append(("  ✅ NO ERROR — Data is correct!", "ok"))
                    items.append((f"  FINAL DATA  :  {data}", "ok"))

            self._write(out, items)

        self._run_button(sec, run)

# ══════════════════════════════════════════════════
if __name__ == "__main__":
    App().mainloop()