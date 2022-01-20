import requests, json, sys

def getargs():
  l = []
  print(f"Scanning IP(s):")
  for i in sys.argv[1:]:
    print(i)
    l.append(i)
  return l

def getdata(l):
  ldata = []
  for i in l:
    data = requests.get("https://internetdb.shodan.io/"+i).json()
    ldata.append(data)
  return ldata

def analyze(ldata):
  for i in ldata:
    print(f"\n\nHostname: {i['hostnames']}\nIP: {i['ip']}\nPorts: {i['ports']}\nVulns: {i['vulns']}")

def pointoutissues(ldata):
  print("\n")
  print("Searching for possible high risk IPs...")
  found = False
  for i in ldata:
    if len(i["vulns"]) > 0:
      found = True
      print(f"{i['hostnames'][0]}({i['ip']}) has vulnerabilities:")
      for p in i["vulns"]:
        print(p)
    if not found:
      print("No high risk IPs found")

l = getargs()
ldata = getdata(l)
analyze(ldata)
pointoutissues(ldata)
