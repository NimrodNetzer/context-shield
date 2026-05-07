/**
 * Code.gs — Main entry point for the ContextShield Gmail Add-on.
 *
 * Triggered automatically when the user opens a Gmail message.
 * Extracts a minimal, safe payload from the message and sends it to the
 * backend for analysis.
 *
 * Security boundaries enforced here:
 *  - Only plain text body extracted (no HTML, no raw MIME)
 *  - Attachment NAMES only — content never sent
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

  var sender = message.getFrom() || '';
  var subject = message.getSubject() || '';
  var payload = buildPayload(message, messageId, sender, subject);

  try {
    var result = callAnalyzeEndpoint(payload);
    saveToHistory(messageId, sender, subject, result.verdict, result.score);
    return buildResultCard(result, messageId, sender, subject);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

/**
 * Feedback action — user marks email as Safe.
 */
function onMarkSafe(e) {
  var params = e.parameters;
  submitFeedback(params.messageId, params.originalVerdict, 'SAFE');
  return buildFeedbackConfirmCard('SAFE');
}

/**
 * Feedback action — user marks email as a Threat.
 */
function onMarkThreat(e) {
  var params = e.parameters;
  submitFeedback(params.messageId, params.originalVerdict, 'MALICIOUS');
  return buildFeedbackConfirmCard('MALICIOUS');
}

/**
 * Sends feedback to the backend.
 */
function submitFeedback(messageId, originalVerdict, userVerdict) {
  try {
    callFeedbackEndpoint({
      message_id: messageId,
      original_verdict: originalVerdict,
      user_verdict: userVerdict,
    });
  } catch (err) {
    // Feedback failure is non-critical — log and continue
    Logger.log('Feedback submission failed: ' + err.message);
  }
}

/**
 * Builds a safe, bounded payload from a GmailMessage object.
 * Never includes attachment content.
 */
function buildPayload(message, messageId, sender, subject) {
  var rawHeaders = parseAuthHeaders(message);
  var attachmentNames = getAttachmentNames(message);

  var bodyPlain = message.getPlainBody() || '';
  if (bodyPlain.length > BODY_MAX_CHARS) {
    bodyPlain = bodyPlain.substring(0, BODY_MAX_CHARS);
  }

  return {
    message_id: messageId,
    sender: sender,
    reply_to: message.getReplyTo() || null,
    subject: subject,
    body_plain: bodyPlain,
    headers: rawHeaders,
    attachment_names: attachmentNames,
  };
}

/**
 * Extracts SPF/DKIM/DMARC verdicts from raw message headers.
 */
function parseAuthHeaders(message) {
  var headers = { spf: null, dkim: null, dmarc: null };

  try {
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
