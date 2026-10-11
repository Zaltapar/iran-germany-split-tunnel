#!/usr/bin/env python3
"""render_multi.py — Phase 2 multi-carrier config renderer (host-side).

Purpose:
  Appends a second VLESS+Reality instance (B) to the live single-carrier
  config, deep-copying instance A's exact shape so A stays byte-identical.
  Used during Phase 2 staging deployment on the Germany and Iran hosts.

Security:
  Never prints key material: the private key (Germany) is read from a 0600
  file; the public key (consumer) is read from a file or passed explicitly.
  All arguments are via argv (operator-supplied at runtime); no hardcoded
  host secrets, tokens, or credentials are embedded in this script.

Host-specific references (documented, not secrets):
  Instance B uses port 2053 (Germany) and 10803 (Iran loopback).
  The original staging target was 91.107.152.1:2053; the host/port are
  passed via --downhost/--downport and are not hardcoded here.

Usage:
  render_multi.py germany  <live_cfg> <out> --sni S --shortid H --uuid U --privkeyfile F
  render_multi.py consumer <live_cfg> <out> --sni S --shortid H --uuid U --pubkeyfile F --downhost D --downport P
"""
import argparse, copy, json, sys

def load(p):
    with open(p) as f:
        return json.load(f)

def write(p, obj):
    with open(p, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")

def germany(cfg, sni, shortid, uuid, priv):
    inboundA = next(i for i in cfg["inbounds"] if i.get("tag") == "split-down")
    outA = next(o for o in cfg["outbounds"] if o.get("tag") == "to-splitter")
    inb = copy.deepcopy(inboundA)
    inb["tag"] = "split-down-b"
    inb["port"] = 2053
    inb["listen"] = "0.0.0.0"
    inb["settings"]["clients"] = [{"id": uuid}]
    rs = inb["streamSettings"]["realitySettings"]
    rs["dest"] = sni + ":443"
    rs["serverNames"] = [sni]
    rs["shortIds"] = [shortid]
    rs["privateKey"] = priv
    cfg["inbounds"].append(inb)
    ob = copy.deepcopy(outA)
    ob["tag"] = "to-splitter-b"
    ob["settings"]["redirect"] = "127.0.0.1:9003"
    cfg["outbounds"].append(ob)
    rule = {"inboundTag": ["split-down-b"], "outboundTag": "to-splitter-b"}
    cfg["routing"]["rules"].append(rule)
    return cfg

def consumer(cfg, sni, shortid, uuid, pub, downhost, downport):
    inbA = next(i for i in cfg["inbounds"] if i.get("port") == 10802)
    outA = next(o for o in cfg["outbounds"] if o.get("protocol") == "vless")
    inb = copy.deepcopy(inbA)
    inb["tag"] = "split-down-serve-b"
    inb["port"] = 10803
    inb["listen"] = "127.0.0.1"
    inb["settings"]["address"] = downhost
    inb["settings"]["port"] = int(downport)
    cfg["inbounds"].append(inb)
    ob = copy.deepcopy(outA)
    ob["tag"] = "reality-out-b"
    vn = ob["settings"]["vnext"][0]
    vn["address"] = downhost
    vn["port"] = int(downport)
    vn["users"][0]["id"] = uuid
    rs = ob["streamSettings"]["realitySettings"]
    rs["dest"] = sni + ":443"
    rs["serverName"] = sni
    rs["publicKey"] = pub
    rs["shortId"] = shortid
    cfg["outbounds"].append(ob)
    ruleA = next(r for r in cfg["routing"]["rules"] if r.get("inboundTag") and "split-down-serve" in r["inboundTag"])
    rb = copy.deepcopy(ruleA)
    rb["inboundTag"] = ["split-down-serve-b"]
    rb["outboundTag"] = "reality-out-b"
    cfg["routing"]["rules"].append(rb)
    return cfg

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["germany", "consumer"])
    ap.add_argument("live_cfg")
    ap.add_argument("out")
    ap.add_argument("--sni", required=True)
    ap.add_argument("--shortid", required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--privkeyfile")
    ap.add_argument("--pubkeyfile")
    ap.add_argument("--pubkey")
    ap.add_argument("--downhost")
    ap.add_argument("--downport")
    a = ap.parse_args()
    cfg = load(a.live_cfg)
    if a.mode == "germany":
        with open(a.privkeyfile) as f:
            priv = f.read().strip()
        write(a.out, germany(cfg, a.sni, a.shortid, a.uuid, priv))
        sys.stderr.write("germany multi rendered -> %s\n" % a.out)
    else:
        pub = a.pubkey or open(a.pubkeyfile).read().strip()
        write(a.out, consumer(cfg, a.sni, a.shortid, a.uuid, pub, a.downhost, a.downport))
        sys.stderr.write("consumer multi rendered -> %s\n" % a.out)

if __name__ == "__main__":
    main()
