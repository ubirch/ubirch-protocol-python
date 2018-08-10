import ubirch

api = ubirch.API(debug=True, env="demo")

msg = "96cd0013b04c082e31a14945b594db7f5e55bc8d32da0040a689dbe084770a13a4429ea4a0d689e12aedd49172e5703aa54299e38d29cd2c7b5c18e2773c027e2cf8914af2f955cf034d48ee379509b332fa1f694b57d80f5382a27473ce5b6805bca17622da0040f3527182c311fc550485ca051ff8a61edb1b0db375aaf56404ee3911012aafeab35e420a1a763a8fc3d1c3befd98e4703b46a8e9271de90d3fe16ddbec534508"

r = api.send(bytes.fromhex(msg))
print("{}: {}".format(r.status_code, r.content))