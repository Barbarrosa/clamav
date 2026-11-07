import importlib.util, subprocess, re, struct, json, hashlib
from pathlib import Path
p='/workspace/clamav/tools/compact-memory/top-six-qualification/query_code_audit.py'
s=importlib.util.spec_from_file_location('q',p);q=importlib.util.module_from_spec(s);s.loader.exec_module(q)
paths={
 'baseline':Path('/workspace/clamav-retained-build/libclamav/libclamav.so.14.0.0'),
 'candidate':Path('/workspace/clamav-system-build/libclamav/libclamav.so.14.0.0')}
raw={k:v.read_bytes() for k,v in paths.items()}

def cstring(role,addr):
 data=raw[role]
 assert data[:6]==b'\x7fELF\x02\x01'
 phoff=struct.unpack_from('<Q',data,32)[0]
 phentsz,phnum=struct.unpack_from('<HH',data,54)
 for i in range(phnum):
  typ,flags,off,vaddr,paddr,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*phentsz)
  if typ==1 and vaddr<=addr<vaddr+filesz:
   start=off+addr-vaddr; stop=min(off+filesz,start+4096)
   end=data.find(b'\0',start,stop)
   assert end>=start
   return data[start:end+1]
 raise ValueError('target not in file-backed PT_LOAD')

rows=[]
for names in q.FUNCTIONS.values():
 for name in names:
  dis={k:subprocess.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+name,str(path)],text=True) for k,path in paths.items()}
  parsed={k:q.parse_disassembly(v) for k,v in dis.items()}
  inst={k:[m.group(2) for line in txt.splitlines() if (m:=q.INSTRUCTION.match(line)) and not q.is_padding(m.group(2))] for k,txt in dis.items()}
  assert len(inst['baseline'])==len(inst['candidate'])
  mismatches=[]
  for i,(a,b) in enumerate(zip(parsed['baseline']['nonpadding_cfg'],parsed['candidate']['nonpadding_cfg'])):
   if a==b: continue
   pa=re.fullmatch(r'(lea <rip-displacement>\(%rip\),%\w+ # )<[^>]+>',a)
   pb=re.fullmatch(r'(lea <rip-displacement>\(%rip\),%\w+ # )<[^>]+>',b)
   assert pa and pb and pa.group(1)==pb.group(1),(name,i,a,b)
   targets={k:int(re.search(r'#\s+([0-9a-fA-F]+)\s+<',inst[k][i]).group(1),16) for k in inst}
   strings={k:cstring(k,v) for k,v in targets.items()}
   assert strings['baseline']==strings['candidate'],(name,i,strings)
   mismatches.append({'instruction_index':i,'target_vaddr':targets,'target_cstring_bytes':len(strings['baseline']),'target_cstring_sha256':hashlib.sha256(strings['baseline']).hexdigest(),'target_bytes_equal':True})
  rows.append({'function':name,'nonpadding_instructions':len(inst['baseline']),'mismatch_count':len(mismatches),'all_cfg_differences_are_equal_target_cstring_addresses':True,'differences':mismatches})
r={'schema_version':1,'implementation_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'binaries':{k:{'path':str(paths[k]),'sha256':hashlib.sha256(v).hexdigest()} for k,v in raw.items()},'functions':rows,'summary':{'functions_checked':len(rows),'functions_matching_except_verified_equal_cstring_addresses':len(rows),'verified_cstring_operand_pairs':sum(x['mismatch_count'] for x in rows)},'limitations':['Supplementary classification; does not change conservative query_code_audit strict/CFG match counts.','Checks only selected instructions and file-backed NUL-terminated targets, not all data, callees, whole-engine equivalence or runtime timing.','Instruction addresses, architectural NOPs, code alignment and hardware/cache behavior may differ.']}
Path('/workspace/top-six-final-rip-target-check.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r['summary']))
