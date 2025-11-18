# -*- coding: utf-8 -*-
# analyseur_disques_profond.py
# GPLv3 – Projet Kerberos – Sécurité éthique locale pour vieux PCs (Win 7/10)
# 🛡️ https://liberapay.com/EthicalKerberos/ | Licence : GNU GPLv3

# === GESTIONNAIRE D'ERREURS GLOBAL – KERBEROS DEBUG ===
import sys
import traceback
import tkinter as tk
from tkinter import messagebox

def kerberos_excepthook(exc_type, exc_value, exc_tb):
    err = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    print("💥 ERREUR KERBEROS :\n" + err, file=sys.stderr)
    try:
        tmp = tk.Tk()
        tmp.withdraw()
        messagebox.showerror("💥 Kerberos – Plantage critique", 
                             f"Type : {exc_type.__name__}\nErreur : {exc_value}\n\nConsulter la console.")
        tmp.destroy()
    except: pass
    if not getattr(sys, 'frozen', False):
        input("\n🔴 Appuyez sur Entrée pour quitter...")
sys.excepthook = kerberos_excepthook
# === FIN GESTIONNAIRE ===

import os
import platform
import psutil
from datetime import datetime
from tkinter import ttk, scrolledtext

# === CONFIG KERBEROS ===
BG = "#1e1e1e"
FG = "#00ff00"
FONT_UI = ("Tahoma", 10)
FONT_MONO = ("Consolas", 10)
EXT = {'.py', '.txt', '.log', '.json', '.csv', '.html', '.exe', '.bat', '.ini', '.xml', '.yml', '.yaml'}
MAX_DEPTH = 4

# === FONCTIONS DISQUE (SÉCURISÉES) ===
def safe_list_drives():
    """Retourne les lecteurs Windows fixes (C:, D:, etc.) de façon compatible Win7."""
    if platform.system() != "Windows":
        return []
    try:
        import string
        available = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                # Test rapide sans psutil (évite crash)
                try:
                    os.listdir(drive)
                    available.append(drive)
                except (PermissionError, OSError):
                    # On inclut quand même, l'utilisateur peut vouloir tenter
                    available.append(drive)
        return available
    except Exception:
        return ["C:\\"]  # fallback

def safe_disk_usage(path):
    try:
        usage = psutil.disk_usage(path)
        return f"{usage.used / (1024**3):.1f} / {usage.total / (1024**3):.1f} Go"
    except Exception:
        try:
            # Fallback: taille approximative via os.statvfs (Linux/Unix)
            stat = os.statvfs(path)
            total = (stat.f_blocks * stat.f_frsize) / (1024**3)
            free = (stat.f_bavail * stat.f_frsize) / (1024**3)
            used = total - free
            return f"{used:.1f} / {total:.1f} Go"
        except:
            return "⚠️ Indisponible"

def build_tree(path, prefix="", depth=0, max_depth=4):
    if depth >= max_depth:
        return [f"{prefix}└── [...] (profondeur limitée)"]
    lines = []
    try:
        entries = sorted(os.listdir(path))
    except (OSError, PermissionError, FileNotFoundError):
        return [f"{prefix}📁 [accès refusé]"]
    
    dirs = []
    files_imp = []
    other = 0

    for e in entries:
        full = os.path.join(path, e)
        try:
            if os.path.isdir(full):
                dirs.append(e)
            elif os.path.isfile(full):
                _, ext = os.path.splitext(e)
                if ext.lower() in EXT:
                    files_imp.append(e)
                else:
                    other += 1
        except (OSError, ValueError):
            continue

    total = len(dirs) + len(files_imp) + (1 if other > 0 else 0)
    i = 0

    for d in dirs:
        i += 1
        mark = "└── " if i == total else "├── "
        lines.append(f"{prefix}{mark}📁 {d}")
        lines.extend(build_tree(os.path.join(path, d), prefix + ("    " if i == total else "│   "), depth + 1, max_depth))

    for f in sorted(files_imp):
        i += 1
        mark = "└── " if i == total else "├── "
        icon = "🐍" if f.endswith('.py') else "📄"
        lines.append(f"{prefix}{mark}{icon} {f}")

    if other > 0:
        i += 1
        mark = "└── " if i == total else "├── "
        lines.append(f"{prefix}{mark}📄 [{other} autre(s) fichier(s)]")

    return lines

# === INTERFACE KERBEROS ===
class KerberosDiskAnalyzer:
    def __init__(self, root):
        self.root = root
        root.title("🔍 Kerberos – Analyseur de Disques (Mode Profond)")
        root.geometry("880x680")
        root.configure(bg=BG)

        tk.Label(root, text="KERBEROS – Analyse Profonde de Disques", 
                 fg=FG, bg=BG, font=("Consolas", 13, "bold")).pack(pady=8)

        # Détection disques
        self.drives = safe_list_drives()
        frame = tk.Frame(root, bg=BG)
        frame.pack(pady=5, padx=15, fill=tk.X)

        tk.Label(frame, text="✅ Sélectionnez les lecteurs à analyser :", 
                 fg=FG, bg=BG, font=FONT_UI).pack(anchor="w")

        self.vars = {}
        if self.drives:
            for drv in self.drives:
                var = tk.BooleanVar(value=(drv == "C:\\"))
                self.vars[drv] = var
                tk.Checkbutton(frame, text=drv, variable=var,
                               bg=BG, fg=FG, selectcolor="#333",
                               font=FONT_UI).pack(anchor="w", padx=5, pady=1)
        else:
            tk.Label(frame, text="⚠️ Aucun lecteur détecté (mode restreint).",
                     fg="#ffaa00", bg=BG, font=FONT_UI).pack(anchor="w")

        tk.Button(root, text="🚀 Lancer l'analyse", command=self.analyze,
                  bg="#8b0000", fg="white", font=("Consolas", 11, "bold"),
                  height=1).pack(pady=10)

        self.console = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, font=FONT_MONO,
            bg="#0a0a0a", fg=FG, insertbackground=FG,
            state="normal"
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self.console.bind("<Key>", lambda e: "break")

        self.console.insert(tk.END, "ℹ️ Projet Kerberos – GPLv3\n")
        self.console.insert(tk.END, "   Compatible Windows 7/10 – Analyse locale, sans cloud.\n\n")
        if not self.drives:
            self.console.insert(tk.END, "❗ Aucun lecteur trouvé. Vérifiez les permissions système.\n")

    def analyze(self):
        selected = [d for d, v in self.vars.items() if v.get()] if self.drives else []
        if not selected and self.drives:
            messagebox.showwarning("Sélection requise", "Cochez au moins un lecteur.")
            return

        self.console.delete(1.0, tk.END)
        self.console.insert(tk.END, "🔍 Analyse en cours...\n\n")

        report = []
        report.append("="*60)
        report.append("RAPPORT KERBEROS – ANALYSE PROFONDE DE DISQUES")
        report.append("="*60)
        report.append(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Système : {platform.system()} {platform.release()}")
        report.append(f"Profondeur : {MAX_DEPTH}")
        report.append("Licence : GNU GPLv3 – https://liberapay.com/EthicalKerberos/")
        report.append("="*60)
        report.append("")

        targets = selected if self.drives else ["C:\\"]  # fallback silencieux

        for drv in targets:
            report.append(f"\n{'='*60}\nLECTEUR : {drv}\n{'='*60}")
            report.append(f"📊 Espace : {safe_disk_usage(drv)}")
            report.append("\nArborescence :")
            report.extend(build_tree(drv, max_depth=MAX_DEPTH))
            report.append("")

        report.append("✅ Analyse terminée – Projet Kerberos (GPLv3)")
        full_report = "\n".join(report)
        self.console.insert(tk.END, full_report)

        try:
            with open("rapport_disques_profond.txt", "w", encoding="utf-8") as f:
                f.write(full_report)
            self.console.insert(tk.END, f"\n\n💾 Rapport sauvegardé : rapport_disques_profond.txt")
            messagebox.showinfo("✅ Succès", "Rapport généré avec succès !")
        except Exception as e:
            self.console.insert(tk.END, f"\n\n⚠️ Erreur sauvegarde : {e}")

# === LANCEMENT ===
if __name__ == "__main__":
    root = tk.Tk()
    app = KerberosDiskAnalyzer(root)
    root.mainloop()