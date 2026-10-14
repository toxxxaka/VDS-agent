/* Public-demo authentication layer, loaded before the shared application UI. */
function login(message="") {
  clearWork();
  app.innerHTML=`<section class="auth"><div class="page-kicker"><span>Demo</span>PUBLIC ACCESS</div><h1>Try VDS Agent</h1><p class="sub">This is a test server. Administrative actions are available after installing the software.</p><div class="card"><div class="controls"><button class="primary" id="request">Request login / password</button><button class="secondary" id="open-login">Sign in</button></div><p class="tiny"><span class="demo-spinner hidden" id="wait" aria-hidden="true"></span><span id="request-note">${esc(message)}</span></p></div><div class="card hidden" id="credentials"><h2>Temporary access</h2><p class="sub">Access is valid for 24 hours. You can request a new login later.</p><p><b>Login:</b> <code id="login-name"></code><br><b>Password:</b> <code id="login-password"></code></p></div><div class="card hidden" id="signin"><h2>Sign in</h2><p class="sub">Use Latin letters only.</p><input id="username" autocomplete="username" maxlength="9" placeholder="Login"><input id="password" type="password" autocomplete="current-password" maxlength="15" placeholder="Password"><button class="primary" id="signin-button">Sign in</button><p class="tiny" id="signin-note"></p></div></section>`;
  const openLogin=()=>document.querySelector('#signin').classList.remove('hidden');
  document.querySelector('#open-login').onclick=openLogin;
  document.querySelector('#request').onclick=async()=>{
    const button=document.querySelector('#request'), note=document.querySelector('#request-note'), wait=document.querySelector('#wait');
    button.disabled=true; wait.classList.remove('hidden'); note.textContent='Requesting login credentials…';
    try { await api('/api/demo-access/request',{method:'POST'}); note.textContent='Request sent. Waiting for the owner to share temporary credentials…'; poll(); }
    catch(error) { note.textContent=error.message; button.disabled=false; wait.classList.add('hidden'); }
  };
  const poll=async()=>{
    try {
      const data=await api('/api/demo-access/status');
      if(data.status==='shared'&&data.username&&data.password){
        document.querySelector('#login-name').textContent=data.username;
        document.querySelector('#login-password').textContent=data.password;
        document.querySelector('#credentials').classList.remove('hidden');
        document.querySelector('#wait').classList.add('hidden');
        document.querySelector('#request-note').textContent='Credentials received. They are valid for 24 hours.';
        openLogin(); return;
      }
      if(data.status==='waiting'||data.status==='generated') setTimeout(poll,3000);
    } catch (_) {}
  };
  document.querySelector('#signin-button').onclick=async()=>{
    const username=document.querySelector('#username'), password=document.querySelector('#password'), note=document.querySelector('#signin-note');
    username.value=username.value.replace(/[^A-Za-z]/g,''); password.value=password.value.replace(/[^A-Za-z]/g,'');
    try { await api('/api/demo-access/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})}); await render(); }
    catch(error) { note.textContent=error.message; }
  };
  poll();
}
window.setTimeout(()=>{
  const originalTools=tools;
  tools=function(){
    originalTools();
    const remove=()=>{
      document.querySelector('[data-page-link="backups"]')?.remove();
      document.querySelector('[data-page-link="firewall"]')?.remove();
      const power=document.querySelector('[data-power]');
      if(power){const grid=power.closest('.grid');grid?.previousElementSibling?.remove();grid?.remove();}
    };
    queueMicrotask(remove);
  };
},0);

window.setTimeout(()=>{
  const originalDashboard=dashboard;
  dashboard=async function(){await originalDashboard();document.querySelectorAll('.service-grid .service').forEach(card=>{card.disabled=true;card.onclick=null;card.removeAttribute('data-console-run');const hint=card.querySelector('small');if(hint)hint.textContent='Available in release';});};
  const originalLibrary=library;
  library=async function(){await originalLibrary();const allowed=new Set(['Find large logs, caches and backups','Largest files under a path','Interface, gateway, DNS and HTTP diagnostics','Resources, OOM, SSH and service triage','Generate strong segmented password']);document.querySelectorAll('#app .card').forEach(card=>{if(!allowed.has(card.querySelector('b')?.textContent?.trim()))card.remove();});};
  events=async function(){app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Server events</h1><p class="sub">Demo examples. Full incident history will be available in the release.</p><div class="card incident warning"><b>High CPU</b><p class="sub">Demo status · evidence and remediation will be available in the release.</p></div><div class="card incident warning"><b>Load Average</b><p class="sub">Demo status · evidence and remediation will be available in the release.</p></div>`;bind();};
  recoveryStudio=async function(){app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Recovery Studio</h1><div class="card empty">Recovery workflows will be available in the release.</div>`;bind();};
  stage78Page=async function(){app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>Timeline & service packs</h1><div class="card empty">Timeline, historical evidence and service packs will be available in the release.</div>`;bind();};
  const originalStart=start;
  start=async function(command){const reports={status:['System status','CPU, memory, disk and network resources are available in the dashboard.\n\nDetailed system identity will be available in the release.'],daily:['Daily report','All systems are operating normally.\n\nDetailed daily evidence will be available in the release.'],ping:['Server availability','Server 1 — UP (demo)\nServer 2 — UP (demo)\nServer 3 — UP (demo)\n\nLive availability checks will be available in the release.'],sessions:['SSH sessions','Demo SSH session\n\nSession details will be available in the release.'],sshlogins:['SSH logins','Demo login record\n\nLogin history will be available in the release.']};if(!reports[command])return originalStart(command);const [title,text]=reports[command];app.innerHTML=`<button class="link" data-page-link="tools">← Tools</button><h1>${esc(title)}</h1><div class="card"><pre>${esc(text)}</pre></div>`;bind();};
},0);
window.setTimeout(()=>{const originalMetrics=metrics;metrics=async function(){await originalMetrics();document.querySelector('#app h1')?.insertAdjacentHTML('afterend','<div class="card demo-metrics-note">Demo telemetry. Live server metrics will be available in the release.</div>');};},0);
