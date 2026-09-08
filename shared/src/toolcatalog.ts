// CTF / offensive-security tool catalogue (specification sections 16, 34, 35). A curated, pure,
// dependency-free inventory of the tools an authorized CTF participant commonly needs, grouped by
// category, each with a detection command and per-manager install commands. Compiled from deep
// research of the canonical awesome-ctf catalogues and standard Kali packaging, then curated so it
// is reliable offline; the backend uses it to diff a participant's detected tools against what a
// challenge category needs and to hand the local AI a concrete install plan on first contact.

export type ToolCategory =
  | 'base'
  | 'recon'
  | 'web'
  | 'exploit'
  | 'internal'
  | 'pwn'
  | 'password'
  | 'crypto'
  | 'reverse'
  | 'forensics'
  | 'stego'
  | 'osint'
  | 'mobile';

export type PackageManager = 'apt' | 'pipx' | 'pip' | 'go' | 'gem' | 'cargo' | 'snap';

export type Install = Partial<Record<PackageManager, string>> & { note?: string };

export type Tool = {
  name: string; // the binary/command name used for detection
  category: ToolCategory;
  purpose: string;
  check: string; // shell command that succeeds when the tool is present
  install: Install;
};

const w = (bin: string) => `command -v ${bin}`;
const pymod = (bin: string, mod: string) => `command -v ${bin} || python3 -c "import ${mod}"`;

export const TOOL_CATALOG: readonly Tool[] = [
  // ── base ──────────────────────────────────────────────────────────────────
  { name: 'curl', category: 'base', purpose: 'HTTP client', check: w('curl'), install: { apt: 'curl' } },
  { name: 'wget', category: 'base', purpose: 'HTTP download', check: w('wget'), install: { apt: 'wget' } },
  { name: 'git', category: 'base', purpose: 'Version control', check: w('git'), install: { apt: 'git' } },
  { name: 'python3', category: 'base', purpose: 'Scripting runtime', check: w('python3'), install: { apt: 'python3 python3-pip python3-venv' } },
  { name: 'pipx', category: 'base', purpose: 'Isolated Python app installer', check: w('pipx'), install: { apt: 'pipx' } },
  { name: 'jq', category: 'base', purpose: 'JSON processor', check: w('jq'), install: { apt: 'jq' } },
  { name: 'nc', category: 'base', purpose: 'Netcat, raw TCP/UDP', check: w('nc'), install: { apt: 'netcat-openbsd' } },
  { name: 'openssl', category: 'base', purpose: 'TLS/crypto toolkit', check: w('openssl'), install: { apt: 'openssl' } },
  { name: 'file', category: 'base', purpose: 'Identify file type', check: w('file'), install: { apt: 'file' } },
  { name: 'xxd', category: 'base', purpose: 'Hex dump/patch', check: w('xxd'), install: { apt: 'xxd' } },
  { name: 'unzip', category: 'base', purpose: 'Archive extraction', check: w('unzip'), install: { apt: 'unzip p7zip-full' } },
  { name: 'socat', category: 'base', purpose: 'Multipurpose relay', check: w('socat'), install: { apt: 'socat' } },
  // ── recon / networking ────────────────────────────────────────────────────
  { name: 'nmap', category: 'recon', purpose: 'Port/service discovery', check: w('nmap'), install: { apt: 'nmap' } },
  { name: 'masscan', category: 'recon', purpose: 'Mass port scanner', check: w('masscan'), install: { apt: 'masscan' } },
  { name: 'rustscan', category: 'recon', purpose: 'Fast port scanner', check: w('rustscan'), install: { cargo: 'rustscan', note: 'or download the release binary' } },
  { name: 'zmap', category: 'recon', purpose: 'Internet-wide scanner', check: w('zmap'), install: { apt: 'zmap' } },
  { name: 'subfinder', category: 'recon', purpose: 'Passive subdomain enum', check: w('subfinder'), install: { go: 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' } },
  { name: 'amass', category: 'recon', purpose: 'Subdomain/OSINT enum', check: w('amass'), install: { apt: 'amass', snap: 'amass' } },
  { name: 'httpx', category: 'recon', purpose: 'HTTP prober/toolkit', check: w('httpx'), install: { go: 'github.com/projectdiscovery/httpx/cmd/httpx@latest' } },
  { name: 'naabu', category: 'recon', purpose: 'Fast port scan', check: w('naabu'), install: { go: 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest' } },
  { name: 'dnsx', category: 'recon', purpose: 'DNS toolkit', check: w('dnsx'), install: { go: 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest' } },
  { name: 'tshark', category: 'recon', purpose: 'CLI packet analysis (Wireshark)', check: w('tshark'), install: { apt: 'tshark' } },
  { name: 'tcpdump', category: 'recon', purpose: 'Packet capture', check: w('tcpdump'), install: { apt: 'tcpdump' } },
  { name: 'bettercap', category: 'recon', purpose: 'MITM/network attack framework', check: w('bettercap'), install: { apt: 'bettercap' } },
  // network host discovery (is it up?)
  { name: 'fping', category: 'recon', purpose: 'Fast ICMP host-up sweep across ranges/lists', check: w('fping'), install: { apt: 'fping' } },
  { name: 'hping3', category: 'recon', purpose: 'Custom TCP/UDP/ICMP probes & firewall testing', check: w('hping3'), install: { apt: 'hping3' } },
  { name: 'netdiscover', category: 'recon', purpose: 'Active/passive ARP host discovery', check: w('netdiscover'), install: { apt: 'netdiscover' } },
  { name: 'arp-scan', category: 'recon', purpose: 'ARP layer-2 host discovery', check: w('arp-scan'), install: { apt: 'arp-scan' } },
  { name: 'nbtscan', category: 'recon', purpose: 'NetBIOS name scanner', check: w('nbtscan'), install: { apt: 'nbtscan' } },
  // TLS/SSL scanning
  { name: 'sslscan', category: 'recon', purpose: 'Enumerate SSL/TLS ciphers & config', check: w('sslscan'), install: { apt: 'sslscan' } },
  { name: 'testssl.sh', category: 'recon', purpose: 'Comprehensive TLS/SSL tester', check: w('testssl.sh'), install: { apt: 'testssl.sh' } },
  { name: 'sslyze', category: 'recon', purpose: 'Fast TLS configuration analyzer', check: w('sslyze'), install: { pipx: 'sslyze' } },
  { name: 'tlsx', category: 'recon', purpose: 'TLS grabber/scanner (ProjectDiscovery)', check: w('tlsx'), install: { go: 'github.com/projectdiscovery/tlsx/cmd/tlsx@latest' } },
  // DNS / subdomain enumeration
  { name: 'dnsrecon', category: 'recon', purpose: 'DNS enumeration & zone transfer', check: w('dnsrecon'), install: { apt: 'dnsrecon' } },
  { name: 'dnsenum', category: 'recon', purpose: 'DNS record/subdomain enumeration', check: w('dnsenum'), install: { apt: 'dnsenum' } },
  { name: 'fierce', category: 'recon', purpose: 'DNS reconnaissance/subdomain scan', check: w('fierce'), install: { apt: 'fierce', pipx: 'fierce' } },
  { name: 'assetfinder', category: 'recon', purpose: 'Find related domains/subdomains', check: w('assetfinder'), install: { go: 'github.com/tomnomnom/assetfinder@latest' } },
  { name: 'findomain', category: 'recon', purpose: 'Fast passive subdomain finder', check: w('findomain'), install: { apt: 'findomain', note: 'or download the release binary' } },
  { name: 'sublist3r', category: 'recon', purpose: 'Passive subdomain enumeration', check: w('sublist3r'), install: { apt: 'sublist3r', pipx: 'sublist3r' } },
  { name: 'massdns', category: 'recon', purpose: 'High-performance DNS resolver', check: w('massdns'), install: { apt: 'massdns' } },
  { name: 'puredns', category: 'recon', purpose: 'Accurate subdomain bruteforce/resolve', check: w('puredns'), install: { go: 'github.com/d3mondev/puredns/v2@latest', note: 'requires massdns' } },
  { name: 'shuffledns', category: 'recon', purpose: 'massdns wrapper for subdomain resolve/brute', check: w('shuffledns'), install: { go: 'github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest' } },
  { name: 'alterx', category: 'recon', purpose: 'Subdomain permutation/wordlist generator', check: w('alterx'), install: { go: 'github.com/projectdiscovery/alterx/cmd/alterx@latest' } },
  // network intelligence & visual recon
  { name: 'asnmap', category: 'recon', purpose: 'Map an ASN to its CIDR ranges', check: w('asnmap'), install: { go: 'github.com/projectdiscovery/asnmap/cmd/asnmap@latest' } },
  { name: 'mapcidr', category: 'recon', purpose: 'CIDR/IP range manipulation', check: w('mapcidr'), install: { go: 'github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest' } },
  { name: 'cdncheck', category: 'recon', purpose: 'Detect CDN/WAF/cloud behind an IP', check: w('cdncheck'), install: { go: 'github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest' } },
  { name: 'uncover', category: 'recon', purpose: 'Query Shodan/Censys/Fofa for exposed hosts', check: w('uncover'), install: { go: 'github.com/projectdiscovery/uncover/cmd/uncover@latest' } },
  { name: 'httprobe', category: 'recon', purpose: 'Probe for working HTTP/HTTPS servers', check: w('httprobe'), install: { go: 'github.com/tomnomnom/httprobe@latest' } },
  { name: 'gowitness', category: 'recon', purpose: 'Web screenshot / visual recon', check: w('gowitness'), install: { go: 'github.com/sensepost/gowitness@latest' } },
  { name: 'aquatone', category: 'recon', purpose: 'Visual inspection of hosts across ports', check: w('aquatone'), install: { apt: 'aquatone' } },
  // ── web ───────────────────────────────────────────────────────────────────
  { name: 'ffuf', category: 'web', purpose: 'Content/parameter fuzzing', check: w('ffuf'), install: { apt: 'ffuf', go: 'github.com/ffuf/ffuf/v2@latest' } },
  { name: 'feroxbuster', category: 'web', purpose: 'Recursive content discovery', check: w('feroxbuster'), install: { apt: 'feroxbuster', cargo: 'feroxbuster' } },
  { name: 'gobuster', category: 'web', purpose: 'Directory/DNS/vhost brute', check: w('gobuster'), install: { apt: 'gobuster', go: 'github.com/OJ/gobuster/v3@latest' } },
  { name: 'wfuzz', category: 'web', purpose: 'Web fuzzer', check: w('wfuzz'), install: { apt: 'wfuzz', pipx: 'wfuzz' } },
  { name: 'dirsearch', category: 'web', purpose: 'Content discovery', check: w('dirsearch'), install: { pipx: 'dirsearch' } },
  { name: 'nuclei', category: 'web', purpose: 'Templated vuln scanning', check: w('nuclei'), install: { go: 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' } },
  { name: 'nikto', category: 'web', purpose: 'Web server scanner', check: w('nikto'), install: { apt: 'nikto' } },
  { name: 'sqlmap', category: 'web', purpose: 'SQL injection detection/exploitation', check: w('sqlmap'), install: { apt: 'sqlmap', pipx: 'sqlmap' } },
  { name: 'commix', category: 'web', purpose: 'Command-injection exploitation', check: w('commix'), install: { apt: 'commix', pipx: 'commix' } },
  { name: 'wpscan', category: 'web', purpose: 'WordPress scanner', check: w('wpscan'), install: { gem: 'wpscan' } },
  { name: 'whatweb', category: 'web', purpose: 'Web technology fingerprint', check: w('whatweb'), install: { apt: 'whatweb' } },
  { name: 'wafw00f', category: 'web', purpose: 'WAF detection', check: w('wafw00f'), install: { apt: 'wafw00f', pipx: 'wafw00f' } },
  { name: 'arjun', category: 'web', purpose: 'HTTP parameter discovery', check: w('arjun'), install: { pipx: 'arjun' } },
  { name: 'dalfox', category: 'web', purpose: 'XSS scanner', check: w('dalfox'), install: { go: 'github.com/hahwul/dalfox/v2@latest' } },
  { name: 'xsser', category: 'web', purpose: 'Automated XSS testing', check: w('xsser'), install: { apt: 'xsser' } },
  { name: 'katana', category: 'web', purpose: 'Crawler', check: w('katana'), install: { go: 'github.com/projectdiscovery/katana/cmd/katana@latest' } },
  { name: 'gau', category: 'web', purpose: 'Fetch known URLs (archives)', check: w('gau'), install: { go: 'github.com/lc/gau/v2/cmd/gau@latest' } },
  { name: 'waybackurls', category: 'web', purpose: 'Wayback URL discovery', check: w('waybackurls'), install: { go: 'github.com/tomnomnom/waybackurls@latest' } },
  { name: 'wapiti', category: 'web', purpose: 'Black-box web vuln scanner (SQLi/XSS/SSRF/XXE)', check: w('wapiti'), install: { apt: 'wapiti' } },
  { name: 'zaproxy', category: 'web', purpose: 'OWASP ZAP DAST proxy/scanner', check: w('zaproxy'), install: { apt: 'zaproxy' } },
  { name: 'skipfish', category: 'web', purpose: 'High-speed web recon scanner (Google)', check: w('skipfish'), install: { apt: 'skipfish' } },
  { name: 'jaeles', category: 'web', purpose: 'Signature-based web vuln scanner', check: w('jaeles'), install: { go: 'github.com/jaeles-project/jaeles@latest' } },
  { name: 'dirb', category: 'web', purpose: 'Classic web content brute-forcer', check: w('dirb'), install: { apt: 'dirb' } },
  { name: 'joomscan', category: 'web', purpose: 'Joomla vulnerability scanner', check: w('joomscan'), install: { apt: 'joomscan' } },
  { name: 'droopescan', category: 'web', purpose: 'Drupal/SilverStripe scanner', check: w('droopescan'), install: { pipx: 'droopescan' } },
  { name: 'cmseek', category: 'web', purpose: 'CMS detection & enumeration', check: w('cmseek'), install: { apt: 'cmseek', note: 'or git clone Tuhinshubhra/CMSeeK' } },
  { name: 'xsstrike', category: 'web', purpose: 'Advanced XSS detection suite', check: 'command -v xsstrike || test -f ~/XSStrike/xsstrike.py', install: { note: 'git clone https://github.com/s0md3v/XSStrike && pip install -r XSStrike/requirements.txt' } },
  { name: 'paramspider', category: 'web', purpose: 'Mine parameters from web archives', check: w('paramspider'), install: { pipx: 'git+https://github.com/devanshbatham/paramspider' } },
  { name: 'x8', category: 'web', purpose: 'Hidden HTTP parameter discovery', check: w('x8'), install: { cargo: 'x8' } },
  { name: 'interactsh-client', category: 'web', purpose: 'Out-of-band (SSRF/blind) interaction testing', check: w('interactsh-client'), install: { go: 'github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest' } },
  // ── exploit ───────────────────────────────────────────────────────────────
  { name: 'msfconsole', category: 'exploit', purpose: 'Metasploit framework', check: w('msfconsole'), install: { apt: 'metasploit-framework', note: 'or the official Rapid7 installer' } },
  { name: 'searchsploit', category: 'exploit', purpose: 'Exploit-DB search', check: w('searchsploit'), install: { apt: 'exploitdb' } },
  { name: 'cvemap', category: 'exploit', purpose: 'Navigate/lookup CVEs (ProjectDiscovery)', check: w('cvemap'), install: { go: 'github.com/projectdiscovery/cvemap/cmd/cvemap@latest' } },
  // ── internal / lateral movement / Active Directory ────────────────────────
  { name: 'nxc', category: 'internal', purpose: 'NetExec: sweep SMB/WinRM/LDAP/SSH/MSSQL across a subnet, spray creds, enum shares', check: w('nxc'), install: { pipx: 'git+https://github.com/Pennyw0rth/NetExec' } },
  { name: 'enum4linux-ng', category: 'internal', purpose: 'SMB/Windows enumeration (modern)', check: w('enum4linux-ng'), install: { pipx: 'enum4linux-ng', apt: 'enum4linux-ng' } },
  { name: 'smbmap', category: 'internal', purpose: 'SMB share enumeration & access check', check: w('smbmap'), install: { apt: 'smbmap' } },
  { name: 'smbclient', category: 'internal', purpose: 'SMB client for share access', check: w('smbclient'), install: { apt: 'smbclient' } },
  { name: 'rpcclient', category: 'internal', purpose: 'MS-RPC enumeration (users/shares/policy)', check: w('rpcclient'), install: { apt: 'smbclient' } },
  { name: 'showmount', category: 'internal', purpose: 'List NFS exports', check: w('showmount'), install: { apt: 'nfs-common' } },
  { name: 'snmpwalk', category: 'internal', purpose: 'SNMP enumeration', check: w('snmpwalk'), install: { apt: 'snmp' } },
  { name: 'onesixtyone', category: 'internal', purpose: 'Fast SNMP community scanner', check: w('onesixtyone'), install: { apt: 'onesixtyone' } },
  { name: 'ldapsearch', category: 'internal', purpose: 'LDAP/AD directory enumeration', check: w('ldapsearch'), install: { apt: 'ldap-utils' } },
  { name: 'ldapdomaindump', category: 'internal', purpose: 'Dump AD info over LDAP to HTML/JSON', check: w('ldapdomaindump'), install: { pipx: 'ldapdomaindump' } },
  { name: 'impacket', category: 'internal', purpose: 'AD/network attack scripts (secretsdump, psexec, wmiexec, GetUserSPNs)', check: 'command -v impacket-secretsdump || command -v secretsdump.py', install: { apt: 'impacket-scripts', pipx: 'impacket' } },
  { name: 'responder', category: 'internal', purpose: 'LLMNR/NBT-NS/mDNS poisoning to capture hashes', check: 'command -v responder || command -v Responder.py', install: { apt: 'responder' } },
  { name: 'kerbrute', category: 'internal', purpose: 'Kerberos user enumeration & password spraying', check: w('kerbrute'), install: { go: 'github.com/ropnop/kerbrute@latest' } },
  { name: 'bloodhound-python', category: 'internal', purpose: 'Collect AD attack-path data (BloodHound ingestor)', check: w('bloodhound-python'), install: { pipx: 'bloodhound' } },
  { name: 'certipy', category: 'internal', purpose: 'AD Certificate Services (ADCS) enumeration & abuse', check: w('certipy'), install: { pipx: 'certipy-ad' } },
  { name: 'evil-winrm', category: 'internal', purpose: 'WinRM shell for Windows targets', check: w('evil-winrm'), install: { apt: 'evil-winrm', gem: 'evil-winrm' } },
  { name: 'chisel', category: 'internal', purpose: 'Fast TCP/UDP tunneling over HTTP (pivoting)', check: w('chisel'), install: { go: 'github.com/jpillora/chisel@latest' } },
  { name: 'ligolo-ng', category: 'internal', purpose: 'Modern tunneling/pivoting via a TUN interface', check: 'command -v ligolo-proxy || test -d ~/ligolo-ng', install: { note: 'download proxy + agent releases from github.com/nicocha30/ligolo-ng' } },
  { name: 'sshuttle', category: 'internal', purpose: 'VPN-like pivoting over an SSH session', check: w('sshuttle'), install: { apt: 'sshuttle', pipx: 'sshuttle' } },
  { name: 'proxychains4', category: 'internal', purpose: 'Route tools through a proxy/pivot chain', check: 'command -v proxychains4 || command -v proxychains', install: { apt: 'proxychains4' } },
  // ── pwn / binary exploitation ─────────────────────────────────────────────
  { name: 'pwntools', category: 'pwn', purpose: 'Exploit development (python)', check: pymod('pwn', 'pwn'), install: { pipx: 'pwntools', pip: 'pwntools' } },
  { name: 'gdb', category: 'pwn', purpose: 'GNU debugger', check: w('gdb'), install: { apt: 'gdb' } },
  { name: 'pwndbg', category: 'pwn', purpose: 'GDB exploitation plugin', check: 'test -d ~/pwndbg || test -f ~/.gdbinit', install: { note: 'git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh' } },
  { name: 'ROPgadget', category: 'pwn', purpose: 'ROP gadget finder', check: w('ROPgadget'), install: { pipx: 'ROPgadget', pip: 'ROPgadget' } },
  { name: 'ropper', category: 'pwn', purpose: 'ROP chain builder', check: w('ropper'), install: { pipx: 'ropper', pip: 'ropper' } },
  { name: 'one_gadget', category: 'pwn', purpose: 'libc one-gadget finder', check: w('one_gadget'), install: { gem: 'one_gadget' } },
  { name: 'checksec', category: 'pwn', purpose: 'Binary hardening check', check: w('checksec'), install: { apt: 'checksec' } },
  { name: 'angr', category: 'pwn', purpose: 'Symbolic execution / binary analysis', check: pymod('angr', 'angr'), install: { pipx: 'angr', pip: 'angr' } },
  { name: 'libc-database', category: 'pwn', purpose: 'Identify libc from leaks', check: 'test -d ~/libc-database', install: { note: 'git clone https://github.com/niklasb/libc-database' } },
  // ── password / bruteforce ─────────────────────────────────────────────────
  { name: 'hashcat', category: 'password', purpose: 'GPU password cracking', check: w('hashcat'), install: { apt: 'hashcat' } },
  { name: 'john', category: 'password', purpose: 'John the Ripper cracking', check: w('john'), install: { apt: 'john' } },
  { name: 'hydra', category: 'password', purpose: 'Network login brute force', check: w('hydra'), install: { apt: 'hydra' } },
  { name: 'medusa', category: 'password', purpose: 'Parallel login brute force', check: w('medusa'), install: { apt: 'medusa' } },
  { name: 'patator', category: 'password', purpose: 'Multi-protocol brute-forcer', check: w('patator'), install: { apt: 'patator', pipx: 'patator' } },
  { name: 'fcrackzip', category: 'password', purpose: 'ZIP password cracking', check: w('fcrackzip'), install: { apt: 'fcrackzip' } },
  { name: 'hash-identifier', category: 'password', purpose: 'Identify hash type', check: w('hash-identifier'), install: { apt: 'hash-identifier' } },
  { name: 'name-that-hash', category: 'password', purpose: 'Modern hash identifier', check: w('nth'), install: { pipx: 'name-that-hash' } },
  // ── crypto ────────────────────────────────────────────────────────────────
  { name: 'RsaCtfTool', category: 'crypto', purpose: 'RSA attack toolkit', check: w('RsaCtfTool'), install: { pipx: 'RsaCtfTool', note: 'or git clone RsaCtfTool/RsaCtfTool' } },
  { name: 'sage', category: 'crypto', purpose: 'SageMath for crypto', check: w('sage'), install: { apt: 'sagemath' } },
  { name: 'xortool', category: 'crypto', purpose: 'XOR cipher analysis', check: w('xortool'), install: { pipx: 'xortool', pip: 'xortool' } },
  { name: 'hash_extender', category: 'crypto', purpose: 'Hash length extension', check: 'test -f ~/hash_extender/hash_extender', install: { note: 'git clone https://github.com/iagox86/hash_extender && make -C hash_extender' } },
  { name: 'featherduster', category: 'crypto', purpose: 'Automated cryptanalysis', check: w('featherduster'), install: { note: 'git clone https://github.com/nccgroup/featherduster' } },
  { name: 'z3', category: 'crypto', purpose: 'SMT/theorem prover', check: pymod('z3', 'z3'), install: { pipx: 'z3-solver', pip: 'z3-solver' } },
  // ── reverse engineering ───────────────────────────────────────────────────
  { name: 'r2', category: 'reverse', purpose: 'radare2 RE framework', check: w('r2'), install: { apt: 'radare2' } },
  { name: 'rizin', category: 'reverse', purpose: 'Rizin RE framework', check: w('rizin'), install: { apt: 'rizin' } },
  { name: 'ghidra', category: 'reverse', purpose: 'Decompiler / RE suite (NSA)', check: 'command -v ghidra || command -v ghidraRun', install: { apt: 'ghidra', snap: 'ghidra', note: 'or download from ghidra-sre.org' } },
  { name: 'objdump', category: 'reverse', purpose: 'Disassembler (binutils)', check: w('objdump'), install: { apt: 'binutils' } },
  { name: 'ltrace', category: 'reverse', purpose: 'Library-call tracer', check: w('ltrace'), install: { apt: 'ltrace' } },
  { name: 'strace', category: 'reverse', purpose: 'System-call tracer', check: w('strace'), install: { apt: 'strace' } },
  { name: 'upx', category: 'reverse', purpose: 'Executable packer/unpacker', check: w('upx'), install: { apt: 'upx-ucl' } },
  { name: 'binwalk', category: 'reverse', purpose: 'Firmware/binary analysis', check: w('binwalk'), install: { apt: 'binwalk' } },
  { name: 'uncompyle6', category: 'reverse', purpose: 'Python bytecode decompiler', check: w('uncompyle6'), install: { pipx: 'uncompyle6', pip: 'uncompyle6' } },
  { name: 'gef', category: 'reverse', purpose: 'GDB Enhanced Features', check: 'grep -q gef ~/.gdbinit 2>/dev/null', install: { note: 'bash -c "$(curl -fsSL https://gef.blah.cat/sh)"' } },
  // ── forensics ─────────────────────────────────────────────────────────────
  { name: 'exiftool', category: 'forensics', purpose: 'Metadata extraction', check: w('exiftool'), install: { apt: 'libimage-exiftool-perl' } },
  { name: 'foremost', category: 'forensics', purpose: 'File carving by header', check: w('foremost'), install: { apt: 'foremost' } },
  { name: 'scalpel', category: 'forensics', purpose: 'File carving', check: w('scalpel'), install: { apt: 'scalpel' } },
  { name: 'vol', category: 'forensics', purpose: 'Volatility3 memory forensics', check: w('vol'), install: { pipx: 'volatility3' } },
  { name: 'tsk_recover', category: 'forensics', purpose: 'Sleuth Kit forensics', check: w('tsk_recover'), install: { apt: 'sleuthkit' } },
  { name: 'testdisk', category: 'forensics', purpose: 'Partition/file recovery', check: w('testdisk'), install: { apt: 'testdisk' } },
  { name: 'bulk_extractor', category: 'forensics', purpose: 'Bulk artifact extraction', check: w('bulk_extractor'), install: { apt: 'bulk-extractor' } },
  { name: 'pngcheck', category: 'forensics', purpose: 'PNG integrity/chunks', check: w('pngcheck'), install: { apt: 'pngcheck' } },
  { name: 'aircrack-ng', category: 'forensics', purpose: 'WEP/WPA cracking + pcap', check: w('aircrack-ng'), install: { apt: 'aircrack-ng' } },
  // ── steganography ─────────────────────────────────────────────────────────
  { name: 'steghide', category: 'stego', purpose: 'Hide/extract data in images/audio', check: w('steghide'), install: { apt: 'steghide' } },
  { name: 'zsteg', category: 'stego', purpose: 'PNG/BMP LSB analysis', check: w('zsteg'), install: { gem: 'zsteg' } },
  { name: 'stegseek', category: 'stego', purpose: 'Fast steghide cracker', check: w('stegseek'), install: { apt: 'stegseek', note: 'or download the .deb release' } },
  { name: 'stegcracker', category: 'stego', purpose: 'Steghide brute-force', check: w('stegcracker'), install: { pipx: 'stegcracker' } },
  { name: 'outguess', category: 'stego', purpose: 'Universal stego tool', check: w('outguess'), install: { apt: 'outguess' } },
  { name: 'convert', category: 'stego', purpose: 'ImageMagick image ops', check: w('convert'), install: { apt: 'imagemagick' } },
  { name: 'stegsolve', category: 'stego', purpose: 'Image plane/stego analysis (Java)', check: 'test -f ~/stegsolve.jar', install: { note: 'download stegsolve.jar; run with java -jar' } },
  { name: 'exiv2', category: 'stego', purpose: 'Image metadata manipulation', check: w('exiv2'), install: { apt: 'exiv2' } },
  // ── osint ─────────────────────────────────────────────────────────────────
  { name: 'sherlock', category: 'osint', purpose: 'Hunt usernames across sites', check: w('sherlock'), install: { pipx: 'sherlock-project' } },
  { name: 'theHarvester', category: 'osint', purpose: 'Emails/subdomains/hosts OSINT', check: w('theHarvester'), install: { apt: 'theharvester', pipx: 'theHarvester' } },
  { name: 'holehe', category: 'osint', purpose: 'Check email on sites', check: w('holehe'), install: { pipx: 'holehe' } },
  { name: 'exifprobe', category: 'osint', purpose: 'Deep image metadata probe', check: w('exifprobe'), install: { apt: 'exifprobe' } },
  // ── mobile ────────────────────────────────────────────────────────────────
  { name: 'adb', category: 'mobile', purpose: 'Android Debug Bridge', check: w('adb'), install: { apt: 'adb' } },
  { name: 'jadx', category: 'mobile', purpose: 'DEX/APK to Java decompiler', check: w('jadx'), install: { apt: 'jadx' } },
  { name: 'apktool', category: 'mobile', purpose: 'APK reverse engineering', check: w('apktool'), install: { apt: 'apktool' } },
  { name: 'dex2jar', category: 'mobile', purpose: 'DEX to JAR conversion', check: 'command -v d2j-dex2jar || command -v dex2jar', install: { apt: 'dex2jar' } },
  { name: 'frida', category: 'mobile', purpose: 'Dynamic instrumentation', check: w('frida'), install: { pipx: 'frida-tools' } },
  { name: 'objection', category: 'mobile', purpose: 'Runtime mobile exploration', check: w('objection'), install: { pipx: 'objection' } },
  { name: 'apkleaks', category: 'mobile', purpose: 'Scan APK for secrets/URIs', check: w('apkleaks'), install: { pipx: 'apkleaks' } },
];

export const CATEGORIES: readonly ToolCategory[] = [
  'base',
  'recon',
  'web',
  'exploit',
  'internal',
  'pwn',
  'password',
  'crypto',
  'reverse',
  'forensics',
  'stego',
  'osint',
  'mobile',
];

// Tools a participant is missing. `base` and any requested challenge categories are always relevant;
// with no categories, the whole catalogue is considered. Detection is by tool name (from readiness).
export function missingTools(
  installed: readonly string[],
  categories?: readonly ToolCategory[],
): Tool[] {
  const have = new Set(installed.map((n) => n.toLowerCase()));
  const wanted =
    categories && categories.length ? new Set<ToolCategory>(['base', ...categories]) : null;
  return TOOL_CATALOG.filter(
    (t) => (!wanted || wanted.has(t.category)) && !have.has(t.name.toLowerCase()),
  );
}

// A concrete install plan grouped per package manager, preferring apt, then pipx, go, cargo, gem,
// pip, snap. Tools with no command for any manager are returned as manual notes.
export function installPlan(tools: readonly Tool[]): { commands: string[]; manual: string[] } {
  const order: PackageManager[] = ['apt', 'pipx', 'go', 'cargo', 'gem', 'pip', 'snap'];
  const buckets: Partial<Record<PackageManager, string[]>> = {};
  const manual: string[] = [];
  for (const tool of tools) {
    const mgr = order.find((m) => tool.install[m]);
    if (!mgr) {
      manual.push(`${tool.name}: ${tool.install.note ?? 'install manually'}`);
      continue;
    }
    (buckets[mgr] ??= []).push(tool.install[mgr]!);
    if (tool.install.note) manual.push(`${tool.name}: ${tool.install.note}`);
  }
  const uniq = (xs: string[] | undefined) => [...new Set(xs ?? [])];
  const commands: string[] = [];
  if (buckets.apt)
    commands.push(`sudo apt-get update && sudo apt-get install -y ${uniq(buckets.apt).join(' ')}`);
  for (const pkg of uniq(buckets.pipx)) commands.push(`pipx install ${pkg}`);
  for (const pkg of uniq(buckets.go)) commands.push(`go install ${pkg}`);
  for (const pkg of uniq(buckets.cargo)) commands.push(`cargo install ${pkg}`);
  if (buckets.gem) commands.push(`sudo gem install ${uniq(buckets.gem).join(' ')}`);
  if (buckets.pip) commands.push(`pip install ${uniq(buckets.pip).join(' ')}`);
  if (buckets.snap) commands.push(`sudo snap install ${uniq(buckets.snap).join(' ')}`);
  return { commands, manual: [...new Set(manual)] };
}
