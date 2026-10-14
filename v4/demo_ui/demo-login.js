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
