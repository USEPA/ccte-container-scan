#!/usr/bin/env python3
"""Trivy JSON -> layer-attribution HTML + Markdown step summary.

Env: REPORT_JSON REPORT_TARGET REPORT_SEVERITY REPORT_EXIT_CODE REPORT_MD
     REPORT_HTML REPORT_MAX_ROWS REPORT_BASE_DIFFIDS BASE_IMAGE
Exits 1 on findings (unless REPORT_EXIT_CODE=0) and always on an unreadable report.
"""
import json
import os
import sys

OSPKG = ("alpine", "debian", "ubuntu", "redhat", "rocky", "almalinux", "amazon")

env = os.getenv
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
LANG = ("python-pkg", "node-pkg", "jar", "gobinary")
FIX = {"alpine": "apk add --no-cache --upgrade {}",
       "debian": "apt-get update && apt-get install -y --only-upgrade {}",
       "ubuntu": "apt-get update && apt-get install -y --only-upgrade {}",
       "redhat": "microdnf update -y {}", "rocky": "dnf update -y {}",
       "almalinux": "dnf update -y {}", "amazon": "dnf update -y {}",
       "python-pkg": "pin in requirements.txt -> {}",
       "node-pkg": "bump in package.json and commit the lockfile -> {}",
       "jar": "update the dependency in pom.xml -> {}",
       "gobinary": "rebuild against updated modules -> {}"}
MAX = int(env("REPORT_MAX_ROWS") or "25")
BASE = env("BASE_IMAGE") or "the base image"

rank = lambda s: SEV.index(s) if s in SEV else len(SEV)
plural = lambda n: "" if n == 1 else "s"
cell = lambda v: str("" if v is None else v).replace("|", "\\|").replace("\n", " ").strip()
esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
code = lambda t: "".join(p if i % 2 == 0 else "<code>%s</code>" % p
                         for i, p in enumerate(esc(t).split("`")))

CSS = """
:root{--ink:#14181d;--muted:#5d6774;--faint:#8d97a4;--rule:#dfe4ea;--paper:#f6f7f9;--img:#2d5f8b;--img-bg:#e7eef5;--app:#9a5528;--app-bg:#f6ece3;--crit:#a81f1f;--high:#a86a09}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:400 15px/1.6 "IBM Plex Sans",system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:40px 24px 96px}
h1{font-size:15px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;margin:0 0 20px}
.img{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--muted);word-break:break-all;margin:0 0 28px;padding-bottom:24px;border-bottom:1px solid var(--rule)}
.tally{display:flex;flex-wrap:wrap;gap:32px;margin:0 0 36px}
.t-n{font-family:"IBM Plex Mono",monospace;font-size:30px;font-weight:500;line-height:1}
.t-l{font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-top:7px}
.row{display:grid;grid-template-columns:104px 1fr}
.rail{position:relative;padding:22px 20px 22px 0;text-align:right}
.rail:before{content:"";position:absolute;right:0;top:0;bottom:0;width:1px;background:var(--rule)}
.lidx{font-family:"IBM Plex Mono",monospace;font-size:22px;font-weight:500;color:var(--faint);display:block;margin-bottom:9px}
.chip{display:inline-block;font-family:"IBM Plex Mono",monospace;font-size:11px;font-weight:500;letter-spacing:.06em;padding:3px 8px;border-radius:2px}
.image{background:var(--img-bg);color:var(--img)}.app{background:var(--app-bg);color:var(--app)}
.unclassified{background:#eceef1;color:var(--muted)}.config{background:#ecebf3;color:#5b4a7a}
.body{padding:22px 0 22px 22px;min-width:0}
.cmd{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--muted);margin:0 0 16px;word-break:break-all}
.f{margin:0 0 14px}
.f-h{font-family:"IBM Plex Mono",monospace;font-size:13px;display:flex;flex-wrap:wrap;gap:10px;align-items:baseline}
.sev{font-weight:500;font-size:11px;letter-spacing:.08em;min-width:62px}
.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM,.LOW,.UNKNOWN{color:var(--muted)}
.pkg{color:var(--muted)}
.act{font-size:13.5px;color:var(--muted);margin:5px 0 0 72px;padding-left:12px;border-left:2px solid var(--rule)}
.act.poam{border-left-color:var(--crit);color:var(--ink)}
.fixline{font-size:13px;color:var(--muted);margin:18px 0 0 72px}
.fixline code{font-family:"IBM Plex Mono",monospace;font-size:12px;background:#eceef1;padding:2px 6px;border-radius:2px;word-break:break-all}
.bound{display:grid;grid-template-columns:104px 1fr;align-items:center;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--app)}
.bound span{padding-left:22px;position:relative}
.bound span:before{content:"";position:absolute;left:22px;right:0;top:50%;height:1px;background:var(--app);opacity:.28}
.bound b{background:var(--paper);position:relative;padding-right:12px;font-weight:600}
.clean{font-size:14px;color:var(--muted);padding:22px 0;border-top:1px solid var(--rule)}
@media(max-width:640px){.row,.bound{grid-template-columns:1fr}.rail{text-align:left;padding:20px 0 0}.rail:before{display:none}
.body{padding:8px 0 22px}.act,.fixline{margin-left:0}.bound span{padding-left:0}.bound span:before{left:0}}
"""


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows[:MAX]]
    if len(rows) > MAX:
        out.append("\n_Showing %d of %d. Full detail in the run artifact._" % (MAX, len(rows)))
    return "\n".join(out)


def fixline(pt, rows):
    """Copy-pasteable remediation for one layer's fixable packages."""
    fx = sorted({r["pkg"]: r for r in rows if r["fix"]}.values(), key=lambda r: r["pkg"])
    if not fx:
        return ("No fixed version is published yet. Track upstream, or add a "
                "`.trivyignore` entry with an expiry date if the risk is accepted.")
    spec = " ".join("%s>=%s" % (r["pkg"], r["fix"]) for r in fx[:6])
    more = " (+%d more)" % (len(fx) - 6) if len(fx) > 6 else ""
    return "`%s`%s" % (FIX.get(pt, "upgrade -> {}").format(spec), more)


def load(path):
    try:
        return json.load(open(path)) if path and os.path.exists(path) else None
    except (OSError, ValueError):
        return None


def main():
    path = env("REPORT_JSON") or "trivy-results.json"
    rep = load(path)
    if rep is None:
        # A scan that did not run must never render as a scan that found nothing.
        md = ("## Trivy scan - `%s`\n\n**Scan produced no usable report.** Could not "
              "read `%s`.\n\nTreat this as a failed scan.\n"
              % (env("REPORT_TARGET") or "target", path))
        if env("GITHUB_STEP_SUMMARY"):
            open(env("GITHUB_STEP_SUMMARY"), "a").write(md)
        print(md, file=sys.stderr)
        return 1

    target = env("REPORT_TARGET") or rep.get("ArtifactName") or "target"
    cfg = (rep.get("Metadata") or {}).get("ImageConfig") or {}
    hist = [h for h in cfg.get("history") or [] if not h.get("empty_layer")]
    lmap = {}
    for i, d in enumerate((cfg.get("rootfs") or {}).get("diff_ids") or []):
        c = " ".join(((hist[i].get("created_by") if i < len(hist) else "") or "").split())
        c = c.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ")
        lmap[d] = (i, c[:150] or "(no history metadata)")

    b = load(env("REPORT_BASE_DIFFIDS")) or {}
    meta = b.get("Metadata", {}) if isinstance(b, dict) else {}
    base = set(b if isinstance(b, list) else
               meta.get("ImageConfig", {}).get("rootfs", {}).get("diff_ids")
               or meta.get("DiffIDs") or [])

    groups, extras = {}, []
    for res in rep.get("Results") or []:
        pt, tgt = res.get("Type") or "", res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            d = (v.get("Layer") or {}).get("DiffID") or ""
            i, instr = lmap.get(d, (-1, "(not attributed to a layer)"))
            org = "unclassified" if not base else ("image" if d in base else "app")
            fx = v.get("FixedVersion") or ""
            act = ("No fix published upstream yet." if not fx else
                   "Rebuild on a newer %s." % BASE
                   if org == "image" else
                   "Fixed in %s. Layer origin unknown -- pass a base image ref." % fx
                   if org == "unclassified" else
                   "Update to %s in %s." % (fx, tgt or "the manifest") if pt in LANG else
                   "Pin %s in your Dockerfile install step." % fx)
            groups.setdefault((i, instr, pt, org), []).append(
                dict(pkg=v.get("PkgName"), ins=v.get("InstalledVersion"), fix=fx, act=act,
                     sev=(v.get("Severity") or "UNKNOWN").upper(),
                     id=v.get("VulnerabilityID"), url=v.get("PrimaryURL")))
        for s in res.get("Secrets") or []:
            extras.append(("Secret", (s.get("Severity") or "UNKNOWN").upper(), tgt,
                           s.get("RuleID") or s.get("Title"), ""))
        for m in res.get("Misconfigurations") or []:
            extras.append(("Misconfig", (m.get("Severity") or "UNKNOWN").upper(), tgt,
                           m.get("Title"), m.get("Resolution")))

    # Base layers first, app layers next, unattributed findings last.
    secs = sorted(groups.items(), key=lambda kv: (kv[0][0] < 0, kv[0][0], kv[0][2]))
    for _, rows in secs:
        rows.sort(key=lambda r: (rank(r["sev"]), str(r["pkg"])))
    extras.sort(key=lambda e: rank(e[1]))

    vulns = [r for _, rows in secs for r in rows]
    total, nfix = len(vulns) + len(extras), sum(1 for r in vulns if r["fix"])
    nimg = sum(len(rows) for k, rows in secs if k[3] == "image")
    napp = sum(len(rows) for k, rows in secs if k[3] == "app")
    napp_os = sum(len(rows) for k, rows in secs if k[3] == "app" and k[2] in OSPKG)
    napp_lang = sum(len(rows) for k, rows in secs if k[3] == "app" and k[2] not in OSPKG)
    cnt = {}
    for s in [r["sev"] for r in vulns] + [e[1] for e in extras]:
        cnt[s] = cnt.get(s, 0) + 1

    H = ['<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-'
         'width,initial-scale=1"><title>Layer attribution</title><link rel="stylesheet" href='
         '"https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+'
         'Plex+Sans:wght@400;500;600&display=swap"><style>%s</style>' % CSS,
         '<div class="wrap"><h1>Container scan &mdash; layer attribution</h1>'
         '<p class="img">%s</p><div class="tally">' % esc(target)]
    H += ['<div><div class="t-n">%d</div><div class="t-l">%s</div></div>' % (n, lbl)
          for lbl, n in (("Image level", nimg), ("OS packages", napp_os),
                         ("Language packages", napp_lang), ("No fix available", sum(1 for r in vulns if not r["fix"])),
                         ("Total", total))]
    H.append("</div>")
    if not total:
        H.append('<p class="clean">No findings at the requested severities.</p>')

    drawn = False
    for (i, instr, pt, org), rows in secs:
        if org == "app" and base and not drawn:
            H.append('<div class="bound"><span></span><span><b>base image ends</b>'
                     '</span></div>')
            drawn = True
        chip = ("base" if org == "image" else 
                ("os" if pt in OSPKG else "language") if org == "app" else org)
        H.append('<div class="row"><div class="rail"><span class="lidx">%s</span>'
                 '<span class="chip %s">%s</span></div><div class="body"><p class="cmd">'
                 '%s</p>' % ("&mdash;" if i < 0 else "%02d" % i, org, chip, esc(instr)))
        H += ['<div class="f"><div class="f-h"><span class="sev %s">%s</span><span>%s</span>'
              '<span class="pkg">%s %s &rarr; %s</span></div><div class="act %s">%s</div>'
              '</div>' % (r["sev"], r["sev"], esc(r["id"]), esc(r["pkg"]), esc(r["ins"]),
                          esc(r["fix"] or "none"), "" if r["fix"] else "poam", esc(r["act"]))
              for r in rows]
        H.append('<p class="fixline">%s</p></div></div>' % code(fixline(pt, rows)))
    if extras:
        H.append('<div class="row"><div class="rail"><span class="lidx">&mdash;</span>'
                 '<span class="chip config">config</span></div><div class="body">'
                 '<p class="cmd">secrets and misconfigurations</p>')
        H += ['<div class="f"><div class="f-h"><span class="sev %s">%s</span><span>%s</span>'
              '<span class="pkg">%s</span></div><div class="act">%s</div></div>'
              % (e[1], e[1], esc(e[3] or e[0]), esc(e[2]),
                 esc(e[4] or "See the Trivy rule documentation.")) for e in extras]
        H.append("</div></div>")
    open(env("REPORT_HTML") or "trivy-layers.html", "w").write("".join(H) + "</div>")

    sevs = env("REPORT_SEVERITY") or "CRITICAL,HIGH"
    md = ["## Trivy scan - `%s`" % target, ""]
    if not total:
        md.append("**Clean** - no %s findings." % sevs)
    else:
        md += ["**%d finding%s** - %s. %d of %d vulnerabilities have a published fix."
               % (total, plural(total),
                  ", ".join("%d %s" % (cnt[s], s.lower()) for s in SEV if cnt.get(s)),
                  nfix, len(vulns)), "",
               "Findings are grouped by the image layer that introduced them, so a fix "
               "goes into the layer named in the heading."]
        if not base:
            md += ["", "_Layer origin is unclassified: pass `base-image` to split "
                       "base-image findings from application findings._"]
    for (i, instr, pt, org), rows in secs:
        md += ["", "### Layer %s [%s] - `%s`"
               % ("--" if i < 0 else "%02d" % i, org, cell(instr)),
               "%d finding%s - %d fixable%s"
               % (len(rows), plural(len(rows)), sum(1 for r in rows if r["fix"]),
                  " - `%s` packages" % pt if pt else ""), "",
               table(["Package", "Installed", "Fixed in", "Severity", "ID", "Action"],
                     [["`%s`" % cell(r["pkg"]), cell(r["ins"]),
                       cell(r["fix"]) or "_none yet_", r["sev"],
                       "[%s](%s)" % (cell(r["id"]), r["url"]) if r["url"] else cell(r["id"]),
                       cell(r["act"])] for r in rows]),
               "", "**Fix:** %s" % fixline(pt, rows)]
    if extras:
        md += ["", "### Secrets and misconfigurations", "",
               table(["Kind", "Severity", "Target", "Finding", "Resolution"],
                     [[e[0], e[1], "`%s`" % cell(e[2]), cell(e[3]), cell(e[4])]
                      for e in extras])]

    out = "\n".join(md).rstrip() + "\n"
    if env("REPORT_MD"):
        open(env("REPORT_MD"), "w").write(out)
    if env("GITHUB_OUTPUT"):
        with open(env("GITHUB_OUTPUT"), "a") as fh:
            fh.write("total=%d\nfixable=%d\nimage_level=%d\napp_level=%d\n"
                     "os_level=%d\napp_dep_level=%d\n"
                     % (total, nfix, nimg, napp, napp_os, napp_lang))
            fh.writelines("%s=%d\n" % (s.lower(), cnt.get(s, 0)) for s in SEV)
    print(out)
    return 1 if total and (env("REPORT_EXIT_CODE") or "1") != "0" else 0

if __name__ == "__main__":
    sys.exit(main())