"""Mock DOM only; Node executes no browser or network operation."""
from pathlib import Path
import shutil
import subprocess
import unittest


SCRIPT = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Node {
  constructor(){this.children=[];this.value='';this.handlers={};}
  get firstChild(){return this.children[0];}
  appendChild(n){this.children.push(n);}
  removeChild(n){this.children.splice(this.children.indexOf(n),1);}
  set textContent(v){this.value=String(v);this.children=[];}
  get textContent(){return this.value;}
  set innerHTML(v){throw Error('HTML injection sink');}
  addEventListener(n,f){this.handlers[n]=f;}
}
const panel=new Node(),button=new Node();
const doc={getElementById:id=>id==='runtime-results'?panel:button,
  createElement:()=>new Node()};
const context={};vm.createContext(context);vm.runInContext(fs.readFileSync('src/bff/ui/runtime.js','utf8'),context);
let status=200,body={quality:'UNKNOWN',jobs:[]},calls=[];
const fetcher=async(path,opts)=>{calls.push([path,opts]);return {status,json:async()=>body};};
const view=context.SiteProofRuntime.create(doc,fetcher);
(async()=>{
  assert.equal(await view.refresh(),true);assert(panel.textContent.includes('登録されていません'));
  body={quality:'UNKNOWN',jobs:[{page_id:'<img onerror=evil>',kind:'Mobile',job_id:'j',execution:'COMPLETED',quality:'UNKNOWN',profile_reason:'PROFILE_UNATTESTED',source:'RUNTIME_UNATTESTED',evidence:{artifact_ref:'job/attempt/s.png',digest:'a'.repeat(64)}}]};
  assert.equal(await view.refresh(),true);assert.equal(panel.children.length,1);
  assert(panel.children[0].textContent.includes('<img onerror=evil>'));
  assert(panel.children[0].textContent.includes('品質UNKNOWN'));
  assert(panel.children[0].textContent.includes('job/attempt/s.png'));
  assert.equal(calls[0][0],'/api/baselines/_m1/runtime');
  assert.equal(calls[0][1].credentials,'same-origin');assert.equal(calls[0][1].redirect,'error');
  status=401;assert.equal(await view.refresh(),false);assert.equal(panel.children.length,0);assert(panel.textContent.includes('認証'));
  status=503;assert.equal(await view.refresh(),false);assert(!panel.textContent.includes('登録されていません'));
  status=200;body={quality:'PASS',jobs:[]};assert.equal(await view.refresh(),false);
  view.clear();assert.equal(panel.textContent,'');assert.equal(panel.children.length,0);
})().catch(e=>{console.error(e);process.exitCode=1;});
'''


class RuntimeDOMTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'),'existing Node unavailable')
    def test_read_view_states_injection_and_no_trust_promotion(self):
        result=subprocess.run([shutil.which('node'),'-e',SCRIPT],cwd=Path(__file__).resolve().parents[2],
                              capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
