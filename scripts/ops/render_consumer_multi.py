#!/usr/bin/env python3
"""render_consumer_multi.py — Phase 2 Iran consumer multi-instance renderer.

Purpose:
  Builds the Iran consumer multi-instance config on the host. Instance A is
  kept byte-identical to the live config. Instance B is a deep-copy of A
  with ONLY these fields changed:
    - vnext address/port  -> B down target (supplied via --downhost/--downport)
    - users[0].id         -> B uuid
    - realitySettings.publicKey  -> B public key (read from a file, never printed)
    - realitySettings.shortId    -> B shortId
    - realitySettings.serverName -> B SNI (kept in the SAME singular form as A)

  No `dest` key is added (A has none). This guarantees B has exactly the
  field set the pinned xray build already accepts for A.

Security:
  The public key is read from a file supplied via --b_pubkeyfile; key
  material is never printed. All values are operator-supplied via argv at
  runtime; no host-specific secrets, tokens, or credentials are embedded.

Host-specific references (documented, not secrets):
  The original staging target was 91.107.152.1:2053; the host/port are
  passed via --downhost/--downport and are not hardcoded here.

Usage:
  render_consumer_multi.py <live_cfg> <out> <b_pubkeyfile> --sni S --shortid H --uuid U --downhost D --downport P
"""
import argparse, copy, json, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("live")
    ap.add_argument("out")
    ap.add_argument("b_pubkeyfile")
    ap.add_argument("--sni", required=True)
    ap.add_argument("--shortid", required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--downhost", required=True)
    ap.add_argument("--downport", required=True)
    a = ap.parse_args()

    with open(a.live) as f:
        d = json.load(f)
    with open(a.b_pubkeyfile) as f:
        bpub = f.read().strip()

    inbA = next(i for i in d["inbounds"] if i.get("port") == 10802)
    outA = next(o for o in d["outbounds"] if o.get("protocol") == "vless")

    inbB = copy.deepcopy(inbA)
    inbB["tag"] = "split-down-serve-b"
    inbB["listen"] = "127.0.0.1"
    inbB["port"] = 10803
    inbB["settings"]["address"] = a.downhost
    inbB["settings"]["port"] = int(a.downport)

    outB = copy.deepcopy(outA)
    outB["tag"] = "reality-out-b"
    vn = outB["settings"]["vnext"][0]
    vn["address"] = a.downhost
    vn["port"] = int(a.downport)
    for u in vn["users"]:
        u["id"] = a.uuid
    rs = outB["streamSettings"]["realitySettings"]
    # Mirror A's exact field set: singular "serverName" (A's form). No "dest".
    if "serverNames" in rs:
        rs.pop("serverNames", None)
    rs["serverName"] = a.sni
    rs["publicKey"] = bpub
    rs["shortId"] = a.shortid

    d["inbounds"].append(inbB)
    d["outbounds"].append(outB)
    ruleA = next(r for r in d["routing"]["rules"] if r.get("inboundTag") and "split-down-serve" in r["inboundTag"])
    ruleB = copy.deepcopy(ruleA)
    ruleB["inboundTag"] = ["split-down-serve-b"]
    ruleB["outboundTag"] = "reality-out-b"
    d["routing"]["rules"].append(ruleB)

    with open(a.out, "w") as f:
        json.dump(d, f, indent=2)
        f.write("\n")
    sys.stderr.write("consumer multi rendered -> %s\n" % a.out)

if __name__ == "__main__":
    main()
