/**
 * Code.gs — Main entry point for the ContextShield Gmail Add-on.
 *
 * Security boundaries:
 *  - Only plain text body extracted (no HTML, no raw MIME)
 *  - Attachment names only — content never sent
 *  - Body truncated client-side to 8000 chars before transmission
 *  - Scope: gmail.readonly only
 */

var BODY_MAX_CHARS = 8000;
var ATTACHMENT_MAX_COUNT = 20;
var CHAT_HISTORY_KEY = 'contextshield_chat_history';
var EMAIL_CONTEXT_KEY = 'contextshield_email_context';

// ---------------------------------------------------------------------------
// Contextual trigger
// ---------------------------------------------------------------------------

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

    // Store context for chat — only snippet, never full body
    var bodySnippet = (payload.body_plain || '').substring(0, 500);
    PropertiesService.getUserProperties().setProperty(
      EMAIL_CONTEXT_KEY,
      JSON.stringify({
        sender: sender,
        subject: subject,
        bodySnippet: bodySnippet,
        verdict: result.verdict,
        score: result.score,
        signals: result.signals || [],
      })
    );

    return buildResultCard(result, messageId, sender, subject);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

function onChatSubmit(e) {
  var question = (e.formInput && e.formInput.chat_question) ? e.formInput.chat_question.trim() : '';
  if (!question) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('Please enter a question.'))
      .build();
  }

  var props = PropertiesService.getUserProperties();
  var ctx = {};
  try { ctx = JSON.parse(props.getProperty(EMAIL_CONTEXT_KEY) || '{}'); } catch(e) {}

  // Load existing conversation
  var conversation = [];
  try { conversation = JSON.parse(props.getProperty(CHAT_HISTORY_KEY) || '[]'); } catch(e) {}

  // Get answer from backend
  var answer;
  try {
    answer = callChatEndpoint({
      question: question,
      sender: ctx.sender || '',
      subject: ctx.subject || '',
      body_snippet: ctx.bodySnippet || '',
      verdict: ctx.verdict || 'UNKNOWN',
      score: ctx.score || 0,
      signals: ctx.signals || [],
    });
  } catch (err) {
    answer = 'Could not reach the assistant: ' + err.message;
  }

  // Append to persistent conversation
  conversation.push({ role: 'user', content: question });
  conversation.push({ role: 'assistant', content: answer });

  // Keep last 20 messages (10 exchanges)
  if (conversation.length > 20) {
    conversation = conversation.slice(conversation.length - 20);
  }

  props.setProperty(CHAT_HISTORY_KEY, JSON.stringify(conversation));

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(buildChatCard(conversation))
    )
    .build();
}

function onClearChat(e) {
  PropertiesService.getUserProperties().deleteProperty(CHAT_HISTORY_KEY);
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(buildChatCard([]))
    )
    .build();
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

function onHistoryItemClick(e) {
  var p = e.parameters;
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(
        buildHistoryDetailCard(p.sender, p.subject, p.verdict, parseInt(p.score), p.analyzedAt)
      )
    )
    .build();
}

// ---------------------------------------------------------------------------
// Payload builder
// ---------------------------------------------------------------------------

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

function parseAuthHeaders(message) {
  var headers = { spf: null, dkim: null, dmarc: null };
  try {
    var authResults = message.getHeader ? message.getHeader('Authentication-Results') || '' : '';
    var spfMatch = authResults.match(/spf=(pass|fail|softfail|neutral|none)/i);
    if (spfMatch) headers.spf = spfMatch[1].toLowerCase();
    var dkimMatch = authResults.match(/dkim=(pass|fail|none)/i);
    if (dkimMatch) headers.dkim = dkimMatch[1].toLowerCase();
    var dmarcMatch = authResults.match(/dmarc=(pass|fail|none)/i);
    if (dmarcMatch) headers.dmarc = dmarcMatch[1].toLowerCase();
  } catch (e) {}
  return headers;
}

function getAttachmentNames(message) {
  try {
    return message.getAttachments()
      .slice(0, ATTACHMENT_MAX_COUNT)
      .map(function(a) { return a.getName(); });
  } catch (e) {
    return [];
  }
}
