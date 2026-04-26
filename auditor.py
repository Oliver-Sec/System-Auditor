"""
╔══════════════════════════════════════════════════════╗
║           SYSTEM AUDITOR v1.0  — by [YourName]       ║
║       Educational Cybersecurity Project for GitHub   ║
╚══════════════════════════════════════════════════════╝

What this script does:
  1. Lists the top 10 most memory-hungry processes on your PC.
  2. Lists all active network connections.
  3. Flags any 'Ghost' connections (not from a known browser).
  4. Prints results in a hacker-style ASCII table.
  5. Saves everything to audit_log.txt.

Requirements:
  pip install psutil
"""

import psutil          # For reading processes and connections
import socket          # For translating IP addresses
import datetime        # For timestamps
import os              # For file paths

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

# These are process names we consider "normal" browsers.
# Any network connection NOT owned by these is flagged as a Ghost.
KNOWN_BROWSERS = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "brave.exe",
    "iexplore.exe",
    "safari.exe",
}

LOG_FILE = "audit_log.txt"

# ──────────────────────────────────────────────
# HELPER: ASCII TABLE PRINTER
# ──────────────────────────────────────────────

def make_table(title: str, headers: list, rows: list) -> str:
    """
    Builds a pretty ASCII table as a string.

    Args:
        title   : The title shown above the table.
        headers : A list of column header names, e.g. ["PID", "Name", "RAM"].
        rows    : A list of lists, where each inner list is one row of data.

    Returns:
        A multi-line string that looks like a table when printed.

    HOW IT WORKS:
        1. We figure out the widest value in each column (including the header).
        2. We pad every cell to that width so columns line up.
        3. We draw top/bottom borders with '═' and separators with '─'.
    """
    # Step 1 – Find the max width for each column.
    # Start with the width of the header itself, then compare each data row.
    col_widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Step 2 – Build the border and separator lines.
    total_width = sum(col_widths) + (3 * len(headers)) + 1  # 3 = " | " padding
    top_border    = "╔" + "═" * (total_width - 2) + "╗"
    bottom_border = "╚" + "═" * (total_width - 2) + "╝"
    row_sep       = "╟" + "─" * (total_width - 2) + "╢"

    # Step 3 – Format each row as padded text.
    def fmt_row(data):
        cells = [f" {str(d):<{col_widths[i]}} " for i, d in enumerate(data)]
        return "║" + "│".join(cells) + "║"

    # Step 4 – Assemble the final table string.
    title_line = f"║ {'[ ' + title + ' ]':^{total_width - 4}} ║"
    header_line = fmt_row(headers)

    lines = [
        top_border,
        title_line,
        row_sep,
        header_line,
        row_sep,
    ]
    for row in rows:
        lines.append(fmt_row(row))
    lines.append(bottom_border)

    return "\n".join(lines)


# ──────────────────────────────────────────────
# SECTION 1: TOP 10 MEMORY-HEAVY PROCESSES
# ──────────────────────────────────────────────

def get_top_processes(n: int = 10) -> tuple[str, list]:
    """
    Uses psutil.process_iter() to walk through every running process,
    reads its memory usage, then returns the top N heaviest ones.

    BEGINNER EXPLANATION — What is psutil.process_iter()?
    ─────────────────────────────────────────────────────
    Imagine your computer is a busy office building with hundreds of workers
    (programs) running at the same time. psutil.process_iter() is like a
    security guard walking floor-by-floor and handing you a clipboard about
    each worker: their ID badge number (PID), their name, and how many office
    supplies (RAM) they're using.

    The ['pid', 'name', 'memory_info'] part is called an "attribute list".
    It tells the guard: "Only give me those three facts — I don't need
    everything." This makes the function much faster.

    Each item the guard hands back is a psutil.Process object. We call
    .info on it to read the clipboard data.

    Returns:
        (table_string, raw_rows) – A rendered ASCII table and raw data list.
    """
    process_list = []

    # process_iter() is a generator — it gives us one process at a time.
    # We ask for three pieces of info per process.
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            pid  = proc.info['pid']
            name = proc.info['name'] or "Unknown"
            # memory_info().rss = "Resident Set Size" = RAM actually in use right now.
            # We convert bytes → megabytes by dividing by 1024 twice.
            ram_mb = proc.info['memory_info'].rss / (1024 * 1024)
            process_list.append((pid, name, ram_mb))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Some system processes deny access — we skip them gracefully.
            pass

    # Sort by RAM descending, take the top N.
    process_list.sort(key=lambda x: x[2], reverse=True)
    top = process_list[:n]

    # Build table rows — format RAM to 2 decimal places.
    headers = ["RANK", "PID", "PROCESS NAME", "RAM USED (MB)"]
    rows = []
    for rank, (pid, name, ram) in enumerate(top, start=1):
        rows.append([rank, pid, name, f"{ram:.2f}"])

    table = make_table("TOP 10 MEMORY-HEAVY PROCESSES", headers, rows)
    return table, rows


# ──────────────────────────────────────────────
# SECTION 2: ACTIVE NETWORK CONNECTIONS
# ──────────────────────────────────────────────

def get_network_connections() -> tuple[str, list]:
    """
    Uses psutil.net_connections() to list every open TCP/UDP connection.

    For each connection we try to find the owning process name using its PID.
    This is key for spotting Ghost connections in Section 3.

    Returns:
        (table_string, raw_connection_list)
    """
    # Build a quick lookup: PID → process name, so we can label connections.
    pid_to_name = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_to_name[proc.info['pid']] = proc.info['name'] or "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    connections = []
    # net_connections() returns every socket on the system.
    for conn in psutil.net_connections(kind='inet'):
        # conn.laddr = local address/port    conn.raddr = remote address/port
        local  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
        status = conn.status or "—"
        pid    = conn.pid or 0
        name   = pid_to_name.get(pid, "Unknown")
        connections.append((pid, name, local, remote, status))

    headers = ["PID", "PROCESS", "LOCAL ADDR", "REMOTE ADDR", "STATUS"]
    rows = [[p, n, l, r, s] for p, n, l, r, s in connections]

    table = make_table("ACTIVE NETWORK CONNECTIONS", headers, rows)
    return table, connections


# ──────────────────────────────────────────────
# SECTION 3: GHOST CONNECTION DETECTOR
# ──────────────────────────────────────────────

def detect_ghost_connections(connections: list) -> str:
    """
    A 'Ghost' connection is any ESTABLISHED network connection whose owning
    process is NOT in our KNOWN_BROWSERS list.

    WHY DOES THIS MATTER FOR SECURITY?
    ────────────────────────────────────
    Malware (like a RAT — Remote Access Trojan) often hides by disguising
    itself as a normal-looking process, or running as a process you wouldn't
    notice. If a process you've never heard of is ESTABLISHED to an external
    IP, that's a red flag worth investigating!

    Args:
        connections: The raw list from get_network_connections().

    Returns:
        A rendered ASCII table of Ghost connections (or a "clean" message).
    """
    ghosts = []
    for pid, name, local, remote, status in connections:
        # We only care about ESTABLISHED connections (actively talking to something).
        if status == "ESTABLISHED":
            if name.lower() not in KNOWN_BROWSERS and remote != "—":
                ghosts.append([pid, name, local, remote, "⚠ GHOST?"])

    if not ghosts:
        return make_table(
            "GHOST CONNECTION DETECTOR",
            ["STATUS"],
            [["✔ No ghost connections detected. System looks clean!"]]
        )

    headers = ["PID", "PROCESS", "LOCAL ADDR", "REMOTE ADDR", "FLAG"]
    return make_table("⚠  GHOST CONNECTIONS DETECTED  ⚠", headers, ghosts)


# ──────────────────────────────────────────────
# MAIN — Run everything and save the log
# ──────────────────────────────────────────────

def main():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║          ░██████╗██╗   ██╗███████╗████████╗███████╗███╗░░░  ║
║          ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗░░  ║
║          ╚█████╗░ ╚████╔╝ ███████╗   ██║   █████╗  ██╔██╗   ║
║          ░╚═══██╗ ░╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╗  ║
║          ██████╔╝  ░██║   ███████║   ██║   ███████╗██║ ╚██╗ ║
║          ╚═════╝   ╚═╝    ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║
║                   SYSTEM AUDITOR v1.0                        ║
║               Educational Cybersecurity Tool                 ║
║                  Scan Time: {timestamp}              ║
╚══════════════════════════════════════════════════════════════╝
"""

    print(banner)

    # --- Run all three audits ---
    print("[*] Scanning processes...")
    proc_table, _ = get_top_processes()
    print(proc_table)

    print("\n[*] Scanning network connections...")
    conn_table, raw_connections = get_network_connections()
    print(conn_table)

    print("\n[*] Running Ghost Connection Detector...")
    ghost_table = detect_ghost_connections(raw_connections)
    print(ghost_table)

    footer = f"\n[✔] Audit complete. Results saved to: {os.path.abspath(LOG_FILE)}\n"
    print(footer)

    # --- Save everything to a log file ---
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(banner)
        f.write("\n\n")
        f.write(proc_table)
        f.write("\n\n")
        f.write(conn_table)
        f.write("\n\n")
        f.write(ghost_table)
        f.write(footer)


if __name__ == "__main__":
    main()
