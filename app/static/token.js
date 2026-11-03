/* NetMapper API token köprüsü (T2).
 *
 * API_TOKEN tanımlı bir sunucuda tüm /api/v1/* çağrıları 401 döner.
 * Bu script:
 *   1) fetch'i sarar: X-API-Token header'ını localStorage'dan ekler.
 *   2) WebSocket'i sarar: ?token= sorgu parametresini ekler.
 *   3) 401/gereksiz WS kapanması alırsa operatöre token sorar ve
 *      localStorage("netmapper_api_token")'a kaydeder, isteği tekrarlar.
 * Token yalnızca tarayıcıda saklanır; sunucuya loglanmaz.
 */
(function () {
  "use strict";
  var KEY = "netmapper_api_token";

  function token() { try { return localStorage.getItem(KEY) || ""; } catch (e) { return ""; } }
  function withToken(url, tok) {
    if (!tok || !url) return url;
    var sep = url.indexOf("?") >= 0 ? "&" : "?";
    return url + sep + "token=" + encodeURIComponent(tok);
  }

  var origFetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var tok = token();
    if (tok) {
      var h = new Headers(init.headers || (input && input.headers) || {});
      if (!h.has("X-API-Token")) h.set("X-API-Token", tok);
      init.headers = h;
    }
    return origFetch(input, init).then(function (resp) {
      if (resp.status === 401 && !init.__retried) {
        var entered = window.prompt("NetMapper API token'ı:");
        if (entered && entered.trim()) {
          try { localStorage.setItem(KEY, entered.trim()); } catch (e) {}
          init.__retried = true;
          return window.fetch(input, init);
        }
      }
      return resp;
    });
  };

  var OrigWS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    if (url && typeof url === "string") url = withToken(url, token());
    return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
  };
  window.WebSocket.prototype = OrigWS.prototype;
})();
