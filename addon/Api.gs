/**
 * Api.gs — Backend communication layer.
 *
 * Attaches a Google-signed OIDC identity token to every request so the
 * backend can verify the caller is our specific Apps Script project.
 *
 * The token is fetched fresh on each call — it has a 1-hour TTL but Apps
 * Script caches it automatically. We never store it in Script Properties.
 */

var BACKEND_URL = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');

/**
 * Calls the backend /analyze endpoint.
 * @param {Object} payload - The structured email payload.
 * @returns {Object} Parsed JSON response from the backend.
 * @throws {Error} If the request fails or returns a non-2xx status.
 */
function callAnalyzeEndpoint(payload) {
  if (!BACKEND_URL) {
    throw new Error('BACKEND_URL script property is not set.');
  }

  var token = ScriptApp.getIdentityToken();

  var options = {
    method: 'post',
    contentType: 'application/json',
    headers: {
      'Authorization': 'Bearer ' + token,
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,   // handle errors manually, don't throw on 4xx/5xx
  };

  var response = UrlFetchApp.fetch(BACKEND_URL + '/analyze', options);
  var statusCode = response.getResponseCode();

  if (statusCode === 401 || statusCode === 403) {
    throw new Error('Authentication failed. Check BACKEND_URL and service account permissions.');
  }
  if (statusCode === 429) {
    throw new Error('Rate limit reached. Please wait a moment before re-analyzing.');
  }
  if (statusCode < 200 || statusCode >= 300) {
    throw new Error('Backend returned status ' + statusCode);
  }

  return JSON.parse(response.getContentText());
}
