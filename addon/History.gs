/**
 * History.gs — Analysis history using UserProperties.
 *
 * Stores the last 5 analyzed emails per user in Apps Script UserProperties.
 * UserProperties are per-user, per-script, and persist across sessions.
 *
 * Security: only verdict, score, sender display name, subject, and message ID
 * are stored — never the email body. Consistent with the backend's zero-storage
 * principle.
 */

var HISTORY_KEY = 'contextshield_history';
var MAX_HISTORY = 5;

/**
 * Saves an analysis result to the user's history.
 * Keeps only the most recent MAX_HISTORY entries.
 */
function saveToHistory(messageId, sender, subject, verdict, score) {
  var props = PropertiesService.getUserProperties();
  var history = getHistory();

  // Remove existing entry for this message if re-analyzed
  history = history.filter(function(item) {
    return item.messageId !== messageId;
  });

  // Prepend new entry
  history.unshift({
    messageId: messageId,
    sender: sender.substring(0, 60),
    subject: subject.substring(0, 80),
    verdict: verdict,
    score: score,
    analyzedAt: new Date().toISOString(),
  });

  // Keep only the most recent entries
  history = history.slice(0, MAX_HISTORY);

  props.setProperty(HISTORY_KEY, JSON.stringify(history));
}

/**
 * Returns the user's analysis history as an array, newest first.
 * Returns empty array if no history exists.
 */
function getHistory() {
  try {
    var props = PropertiesService.getUserProperties();
    var raw = props.getProperty(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}
