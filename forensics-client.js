(function(){
  const FPORT = '4001';
  const FHOST = window.location.hostname || '127.0.0.1';
  const FAPI = window.location.protocol + '//' + FHOST + ':' + FPORT;
  const $f = id => document.getElementById(id);
  const tcls = (t,ctx) => ({INCOMING:'fb-in',OUTGOING:'fb-out',MISSED:'fb-miss',REJECTED:'fb-miss',INBOX:'fb-in',SENT:'fb-out',DRAFT:'fb-out',RECEIVED:'fb-in'}[t]||'fb-out');

  // Set download report link
  const dlBtn = $f('f-btn-dl');
  if (dlBtn) dlBtn.href = FAPI + '/report';

  async function fCheckDevice(){
    const dlbl = $f('f-dlbl');
    if (!dlbl) return;
    dlbl.textContent = 'Checking...';
    try{
      const r = await fetch(FAPI + '/status', { signal: AbortSignal.timeout(4000) });
      const d = await r.json();
      if(d.connected){
        $f('f-dot').className = 'f-dot on';
        dlbl.textContent = d.deviceInfo.model || 'Connected';
        $f('f-btn-go').disabled = false;
        $f('f-nodev').style.display = 'none';
      } else {
        $f('f-dot').className = 'f-dot off';
        dlbl.textContent = 'No Device';
        $f('f-btn-go').disabled = true;
        $f('f-nodev').style.display = 'block';
      }
    } catch(e){
      if ($f('f-dot')) $f('f-dot').className = 'f-dot off';
      dlbl.textContent = 'Start forensics-server.js (port 4001)';
      if ($f('f-btn-go')) $f('f-btn-go').disabled = true;
    }
  }

  function fRender(data){
    $f('f-hash').textContent = data.evidenceHash || 'N/A';
    $f('f-ts').textContent = 'Extracted: ' + data.timestamp;
    $f('fs-calls').textContent = (data.callLogs || []).length;
    $f('fs-sms').textContent = (data.sms || []).length;
    $f('fs-contacts').textContent = (data.contacts || []).length;
    $f('fs-photos').textContent = (data.photos || []).length;

    const cl = data.callLogs || [];
    $f('fc-calls').textContent = cl.length + ' records';
    if(cl.length) $f('f-calls-body').innerHTML = '<table class="ftbl"><tr><th>Number</th><th>Name</th><th>Date</th><th>Duration</th><th>Type</th></tr>' + cl.map(c => '<tr><td>' + c.number + '</td><td>' + c.name + '</td><td>' + c.date + '</td><td>' + c.duration + '</td><td><span class="f-badge ' + tcls(c.type) + '">' + c.type + '</span></td></tr>').join('') + '</table>';

    const sm = data.sms || [];
    $f('fc-sms').textContent = sm.length + ' records';
    if(sm.length) $f('f-sms-body').innerHTML = '<table class="ftbl"><tr><th>From/To</th><th>Date</th><th>Type</th><th>Message</th></tr>' + sm.map(s => '<tr><td>' + s.address + '</td><td>' + s.date + '</td><td><span class="f-badge ' + tcls(s.type) + '">' + s.type + '</span></td><td>' + s.body + '</td></tr>').join('') + '</table>';

    const co = data.contacts || [];
    $f('fc-contacts').textContent = co.length + ' records';
    if(co.length) $f('f-contacts-body').innerHTML = '<table class="ftbl"><tr><th>Name</th><th>Number</th></tr>' + co.map(c => '<tr><td>' + c.name + '</td><td>' + c.number + '</td></tr>').join('') + '</table>';

    const wa = data.whatsapp || {};
    if(wa.found){
      $f('fc-wa').textContent = (wa.messages || []).length + ' messages';
      let wh = '<div class="f-hbox"><div class="f-hlbl">DB HASH</div><div class="f-hval">' + wa.hash + '</div></div>';
      if((wa.messages || []).length) wh += '<table class="ftbl"><tr><th>Contact</th><th>Dir</th><th>Date</th><th>Message</th></tr>' + wa.messages.map(m => '<tr><td>' + m.contact + '</td><td><span class="f-badge ' + tcls(m.direction) + '">' + m.direction + '</span></td><td>' + m.date + '</td><td>' + m.message + '</td></tr>').join('') + '</table>';
      $f('f-wa-body').innerHTML = wh;
    }

    const ph = data.photos || [];
    $f('fc-photos').textContent = ph.length + ' files';
    if(ph.length) $f('f-photos-body').innerHTML = '<table class="ftbl"><tr><th>File</th><th>Path</th></tr>' + ph.map(p => '<tr><td>' + p.name + '</td><td style="font-size:9px">' + p.folder + '</td></tr>').join('') + '</table>';

    const ap = data.apps || [];
    $f('fc-apps').textContent = ap.length + ' apps';
    if(ap.length) $f('f-apps-body').innerHTML = '<div class="f-agrid">' + ap.map(a => '<div class="f-aitem" title="' + a + '">' + a + '</div>').join('') + '</div>';
    
    $f('f-results').style.display = 'block';
    if ($f('f-btn-dl')) $f('f-btn-dl').style.display = 'inline-flex';
  }

  async function fExtract(){
    const loading = $f('f-loading');
    const lphase = $f('f-lphase');
    loading.classList.add('show');
    const phases = ['Connecting via ADB...','Extracting call logs...','Extracting SMS...','Pulling contacts...','Searching WhatsApp DB...','Listing media files...','Scanning installed apps...','Generating SHA-256 hash...','Building evidence report...'];
    let pi = 0;
    const iv = setInterval(() => { if(pi < phases.length - 1) lphase.textContent = phases[pi++]; }, 1500);
    try{
      const r = await fetch(FAPI + '/extract', { method: 'POST', signal: AbortSignal.timeout(90000) });
      clearInterval(iv);
      if(!r.ok){ const e = await r.json(); alert('Error: ' + e.error); return; }
      const d = await r.json();
      fRender(d);
    } catch(e){
      clearInterval(iv);
      alert('Cannot connect to forensics-server.js. Make sure it is running locally: node forensics-server.js');
    } finally {
      loading.classList.remove('show');
    }
  }

  const btnGo = $f('f-btn-go');
  const btnRef = $f('f-btn-ref');
  if (btnGo) btnGo.addEventListener('click', fExtract);
  if (btnRef) btnRef.addEventListener('click', fCheckDevice);
  fCheckDevice();
  setInterval(fCheckDevice, 10000);
})();
