/**
 * UI.gs — Card Service builders for the ContextShield add-on.
 *
 * Renders four states:
 *   1. Loading card  — shown immediately while analysis runs
 *   2. Result card   — score, verdict, reasoning, signals, feedback, history
 *   3. Error card    — friendly message when analysis fails
 *   4. Feedback card — confirmation after user submits feedback
 */

var VERDICT_COLORS = {
  SAFE:       '#1e8e3e',
  SUSPICIOUS: '#f9ab00',
  MALICIOUS:  '#d93025',
};

var SCORE_BAR_LENGTH = 10;

/**
 * Builds a filled/empty bar: ■■■■■□□□□□ 50/100
 */
function buildScoreBar(score) {
  var filled = Math.round(score / 10);
  var bar = '';
  for (var i = 0; i < SCORE_BAR_LENGTH; i++) {
    bar += i < filled ? '■' : '□';
  }
  return bar + ' ' + score + '/100';
}

/**
 * Loading card — returned immediately before the backend call.
 */
function buildLoadingCard() {
  var card = CardService.newCardBuilder()
    .setName('contextshield_loading')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ContextShield')
        .setSubtitle('Analyzing email...')
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText()
      .setText('Scanning for threats...')
      .setWrapText(true)
  );
  card.addSection(section);
  return card.build();
}

/**
 * Main result card.
 */
function buildResultCard(result, messageId, sender, subject) {
  var score = result.score || 0;
  var verdict = result.verdict || 'UNKNOWN';
  var reasoning = result.reasoning || [];
  var signals = result.signals || [];

  var card = CardService.newCardBuilder()
    .setName('contextshield_result')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ContextShield')
        .setSubtitle('Email Security Analysis')
    );

  // -- Score + Verdict --
  var scoreSection = CardService.newCardSection();

  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText(verdict)
      .setWrapText(false)
  );

  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Risk Score')
      .setText(buildScoreBar(score))
      .setWrapText(false)
  );

  card.addSection(scoreSection);

  // -- Reasoning --
  if (reasoning.length > 0) {
    var reasonSection = CardService.newCardSection()
      .setHeader('Why')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(2);

    reasoning.forEach(function(line) {
      reasonSection.addWidget(
        CardService.newDecoratedText()
          .setText('• ' + line)
          .setWrapText(true)
      );
    });

    card.addSection(reasonSection);
  }

  // -- Signals --
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

  // -- Feedback --
  var feedbackSection = CardService.newCardSection().setHeader('Was this correct?');

  var markSafeAction = CardService.newAction()
    .setFunctionName('onMarkSafe')
    .setParameters({ messageId: messageId, originalVerdict: verdict });

  var markThreatAction = CardService.newAction()
    .setFunctionName('onMarkThreat')
    .setParameters({ messageId: messageId, originalVerdict: verdict });

  feedbackSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText('✓ Mark as Safe')
          .setOnClickAction(markSafeAction)
      )
      .addButton(
        CardService.newTextButton()
          .setText('⚠ Mark as Threat')
          .setOnClickAction(markThreatAction)
      )
  );

  card.addSection(feedbackSection);

  // -- Re-analyze --
  var actionSection = CardService.newCardSection();
  var reanalyzeAction = CardService.newAction().setFunctionName('onGmailMessage');
  actionSection.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText('Re-analyze')
        .setOnClickAction(reanalyzeAction)
    )
  );
  card.addSection(actionSection);

  // -- History --
  var history = getHistory();
  if (history.length > 0) {
    var historySection = CardService.newCardSection()
      .setHeader('Recent (' + history.length + ')')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    history.forEach(function(item) {
      var label = item.verdict + ' · ' + item.score + '/100';
      var text = (item.subject || '(no subject)').substring(0, 50);
      historySection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(label)
          .setText(text)
          .setBottomLabel(item.sender.substring(0, 40))
          .setWrapText(false)
      );
    });

    card.addSection(historySection);
  }

  return card.build();
}

/**
 * Feedback confirmation card.
 */
function buildFeedbackConfirmCard(userVerdict) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_feedback')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ContextShield')
        .setSubtitle('Feedback recorded')
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText()
      .setText('Marked as: ' + userVerdict + '. Thank you for the correction.')
      .setWrapText(true)
  );
  card.addSection(section);
  return card.build();
}

/**
 * Error card.
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
  section.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText('Retry')
        .setOnClickAction(retryAction)
    )
  );

  card.addSection(section);
  return card.build();
}
