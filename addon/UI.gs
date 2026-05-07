/**
 * UI.gs — Card Service builders for the ContextShield add-on.
 *
 * Renders three states:
 *   1. Result card  — score, verdict, reasoning, signals
 *   2. Error card   — friendly message when analysis fails
 *   3. Loading card — shown while the backend call is in flight (contextual trigger auto-handles this)
 */

/** Verdict → display color mapping using Card Service DecoratedText colors */
var VERDICT_COLORS = {
  SAFE:       '#1e8e3e',   // green
  SUSPICIOUS: '#f9ab00',   // amber
  MALICIOUS:  '#d93025',   // red
};

var SEVERITY_COLORS = {
  low:      '#5f6368',
  medium:   '#f9ab00',
  high:     '#e37400',
  critical: '#d93025',
};

/**
 * Builds the main result card from a backend AnalyzeResponse.
 * @param {Object} result - { score, verdict, reasoning[], signals[] }
 * @returns {Card}
 */
function buildResultCard(result) {
  var score = result.score || 0;
  var verdict = result.verdict || 'UNKNOWN';
  var reasoning = result.reasoning || [];
  var signals = result.signals || [];
  var color = VERDICT_COLORS[verdict] || '#5f6368';

  var card = CardService.newCardBuilder()
    .setName('contextshield_result')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ContextShield')
        .setSubtitle('Email Security Analysis')
    );

  // -- Score + Verdict section --
  var scoreSection = CardService.newCardSection();

  var verdictWidget = CardService.newDecoratedText()
    .setTopLabel('Verdict')
    .setText(verdict)
    .setWrapText(false);

  var scoreWidget = CardService.newDecoratedText()
    .setTopLabel('Risk Score')
    .setText(score.toString() + ' / 100')
    .setWrapText(false);

  scoreSection.addWidget(verdictWidget);
  scoreSection.addWidget(scoreWidget);
  card.addSection(scoreSection);

  // -- Reasoning section --
  if (reasoning.length > 0) {
    var reasonSection = CardService.newCardSection()
      .setHeader('Why')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(1);

    reasoning.forEach(function(line) {
      reasonSection.addWidget(
        CardService.newDecoratedText()
          .setText('• ' + line)
          .setWrapText(true)
      );
    });

    card.addSection(reasonSection);
  }

  // -- Signals section --
  if (signals.length > 0) {
    var signalSection = CardService.newCardSection()
      .setHeader('Signals (' + signals.length + ')')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    signals.forEach(function(signal) {
      var label = signal.type.replace(/_/g, ' ').toUpperCase();
      var text = signal.value ? label + ': ' + signal.value : label;
      signalSection.addWidget(
        CardService.newDecoratedText()
          .setText(text)
          .setTopLabel(signal.severity.toUpperCase())
          .setWrapText(true)
      );
    });

    card.addSection(signalSection);
  }

  // -- Re-analyze button --
  var actionSection = CardService.newCardSection();
  var reanalyzeAction = CardService.newAction().setFunctionName('onGmailMessage');
  var reanalyzeButton = CardService.newTextButton()
    .setText('Re-analyze')
    .setOnClickAction(reanalyzeAction);
  actionSection.addWidget(
    CardService.newButtonSet().addButton(reanalyzeButton)
  );
  card.addSection(actionSection);

  return card.build();
}

/**
 * Builds a friendly error card when the backend call fails.
 * @param {string} message - The error message (user-safe).
 * @returns {Card}
 */
function buildErrorCard(message) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_error')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ContextShield')
        .setSubtitle('Analysis unavailable')
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText()
      .setText(message || 'Could not reach the analysis service. Please try again.')
      .setWrapText(true)
  );

  var retryAction = CardService.newAction().setFunctionName('onGmailMessage');
  var retryButton = CardService.newTextButton()
    .setText('Retry')
    .setOnClickAction(retryAction);
  section.addWidget(CardService.newButtonSet().addButton(retryButton));

  card.addSection(section);
  return card.build();
}
