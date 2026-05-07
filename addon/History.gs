/**
 * History.gs — Analysis history using UserProperties.
 *
 * Stores the last 10 analyzed emails per user in Apps Script UserProperties.
 * Each entry includes verdict, score, signals (risks), sender, and subject.
 * Email body is never stored — consistent with the zero-storage security principle.
 */

var HISTORY_KEY = 'contextshield_history';
var MAX_HISTORY = 10;

/**
 * Saves an analysis result to history, including signals for risk display.
 */
function saveToHistory(messageId, sender, subject, verdict, score, signals) {
  var props = PropertiesService.getUserProperties();
  var history = getHistory();

  history = history.filter(function(item) {
    return item.messageId !== messageId;
  });

  history.unshift({
    messageId: messageId,
    sender: (sender || '').substring(0, 60),
    subject: (subject || '').substring(0, 80),
    verdict: verdict,
    score: score,
    signals: (signals || []).slice(0, 10),
    analyzedAt: new Date().toISOString(),
  });

  history = history.slice(0, MAX_HISTORY);
  props.setProperty(HISTORY_KEY, JSON.stringify(history));
}

/**
 * Returns full history array, newest first.
 */
function getHistory() {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

/**
 * Deletes a single history entry by messageId.
 */
function deleteHistoryItem(messageId) {
  var history = getHistory().filter(function(item) {
    return item.messageId !== messageId;
  });
  PropertiesService.getUserProperties().setProperty(HISTORY_KEY, JSON.stringify(history));
}

/**
 * Deletes all history.
 */
function deleteAllHistory() {
  PropertiesService.getUserProperties().deleteProperty(HISTORY_KEY);
}
