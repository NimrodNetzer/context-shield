/**
 * Code.gs — Main entry point for the ContextShield Gmail Add-on.
 *
 * Triggered automatically when the user opens a Gmail message.
 * Extracts a minimal, safe payload from the message and sends it to the
 * backend for analysis.
 *
 * Security boundaries enforced here:
 *  - Only plain text body extracted (no HTML, no raw MIME)
 *  - Attachment NAMES and MIME types only — content never sent
 *  - Body truncated client-side to 8000 chars before transmission
 *  - Scope requested: gmail.readonly only (cannot send, delete, or modify)
 */

var BODY_MAX_CHARS = 8000;
var ATTACHMENT_MAX_COUNT = 20;

/**
 * Contextual trigger — called each time the user opens a message.
 * @param {Object} e - Gmail add-on event object.
 * @returns {Card} The rendered result card.
 */
function onGmailMessage(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  var payload = buildPayload(message, messageId);

  try {
    var result = callAnalyzeEndpoint(payload);
    return buildResultCard(result);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

/**
 * Builds a safe, bounded payload from a GmailMessage object.
 * Never includes attachment content.
 */
function buildPayload(message, messageId) {
  var rawHeaders = parseAuthHeaders(message);
  var attachmentNames = getAttachmentNames(message);

  var bodyPlain = message.getPlainBody() || '';
  if (bodyPlain.length > BODY_MAX_CHARS) {
    bodyPlain = bodyPlain.substring(0, BODY_MAX_CHARS);
  }

  return {
    message_id: messageId,
    sender: message.getFrom() || '',
    reply_to: message.getReplyTo() || null,
    subject: message.getSubject() || '',
    body_plain: bodyPlain,
    headers: rawHeaders,
    attachment_names: attachmentNames,
  };
}

/**
 * Extracts SPF/DKIM/DMARC verdicts from raw message headers.
 * Apps Script doesn't expose raw headers directly — we parse from
 * the Authentication-Results header via a regex approach on the raw message.
 */
function parseAuthHeaders(message) {
  // Apps Script GmailMessage exposes limited header access.
  // We surface what we can; backend heuristics handle the rest.
  var headers = {
    spf: null,
    dkim: null,
    dmarc: null,
  };

  try {
    // getHeader is available in advanced Gmail service;
    // fall back gracefully if not available.
    var authResults = message.getHeader
      ? message.getHeader('Authentication-Results') || ''
      : '';

    var spfMatch = authResults.match(/spf=(pass|fail|softfail|neutral|none)/i);
    if (spfMatch) headers.spf = spfMatch[1].toLowerCase();

    var dkimMatch = authResults.match(/dkim=(pass|fail|none)/i);
    if (dkimMatch) headers.dkim = dkimMatch[1].toLowerCase();

    var dmarcMatch = authResults.match(/dmarc=(pass|fail|none)/i);
    if (dmarcMatch) headers.dmarc = dmarcMatch[1].toLowerCase();
  } catch (e) {
    // Header access failed — backend will analyze with nulls
  }

  return headers;
}

/**
 * Returns attachment names (not content) — bounded to ATTACHMENT_MAX_COUNT.
 */
function getAttachmentNames(message) {
  try {
    var attachments = message.getAttachments();
    return attachments
      .slice(0, ATTACHMENT_MAX_COUNT)
      .map(function(a) { return a.getName(); });
  } catch (e) {
    return [];
  }
}
