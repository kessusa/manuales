<div id="yt-box" title="Música · M para silenciar"><div id="yt"></div><button id="yt-mute" type="button">♪</button></div>
<div id="yt-note" hidden></div>
<style>
#yt-box{position:fixed;right:16px;bottom:16px;width:200px;height:200px;z-index:9999;background:#000;border-radius:10px;overflow:hidden;box-shadow:0 6px 20px rgba(0,0,0,.45)}
#yt-box iframe{width:200px;height:200px;display:block}
#yt-mute{position:absolute;left:6px;top:6px;width:28px;height:28px;border-radius:50%;border:0;background:rgba(0,0,0,.6);color:#fff;font-size:15px;cursor:pointer}
#yt-mute.off{text-decoration:line-through;opacity:.7}
#yt-note{position:fixed;right:16px;bottom:226px;max-width:320px;z-index:9999;background:rgba(20,30,26,.92);color:#e8f1ec;font:13px/1.45 system-ui,sans-serif;padding:10px 12px;border-radius:8px}
body.capture #yt-box,body.capture #yt-note{display:none}
</style>
<script>
(function () {
  var ID = '7_TdjpquXiA', VOL = 35;
  var player = null, ready = false, playing = false, muted = false, fading = false;
  var lastT = -1, stillSince = 0;
  var note = function (t) { var n = document.getElementById('yt-note'); n.textContent = t; n.hidden = false; };
  if (location.protocol === 'file:') note('Para que suene la música, abre la página desde http://127.0.0.1:8000 (YouTube no funciona con doble clic).');

  // Tiempo actual de la película, leído de la barra de progreso
  var now = function () {
    var bar = document.getElementById('bar'); if (!bar || !window.DURATION) return 0;
    return (parseFloat(bar.style.width) || 0) / 100 * window.DURATION;
  };
  var songAt = function (t) { var d = player.getDuration ? player.getDuration() : 0; return d > 0 ? t % d : t; };

  window.onYouTubeIframeAPIReady = function () {
    player = new YT.Player('yt', { width: 200, height: 200, videoId: ID,
      playerVars: { controls: 0, disablekb: 1, rel: 0, playsinline: 1, iv_load_policy: 3,
        origin: location.protocol.indexOf('http') === 0 ? location.origin : undefined },
      events: {
        onReady: function () { ready = true; player.setVolume(VOL); },
        onError: function (e) { note('YouTube no deja reproducir este vídeo aquí (error ' + e.data + '). Prueba otra versión de la canción.'); }
      } });
  };

  setInterval(function () {
    if (!ready) return;
    var t = now(), moving = Math.abs(t - lastT) > 0.01;
    if (moving) stillSince = Date.now();
    if (window.DURATION && t >= window.DURATION - 0.05) {            // final: fundido
      if (playing && !fading) { fading = true; var v = VOL, k = setInterval(function () { v -= 3; if (v <= 0) { clearInterval(k); player.pauseVideo(); player.setVolume(VOL); playing = false; fading = false; } else player.setVolume(v); }, 120); }
    } else if (moving && !playing) {                                  // arranca o reanuda
      player.seekTo(songAt(t), true); player.setVolume(VOL); player.playVideo(); playing = true;
    } else if (!moving && playing && Date.now() - stillSince > 400) { // pausa
      player.pauseVideo(); playing = false;
    } else if (playing && Math.abs(t - lastT) > 1.5) {                // salto con flechas
      player.seekTo(songAt(t), true);
    }
    lastT = t;
  }, 250);

  var toggle = function () { muted = !muted; if (ready) { muted ? player.mute() : player.unMute(); } document.getElementById('yt-mute').classList.toggle('off', muted); };
  document.getElementById('yt-mute').addEventListener('click', function (e) { e.stopPropagation(); toggle(); });
  addEventListener('keydown', function (e) { if (e.key === 'm' || e.key === 'M') toggle(); });

  var tag = document.createElement('script'); tag.src = 'https://www.youtube.com/iframe_api'; document.head.appendChild(tag);
})();
</script>
