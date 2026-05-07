/**
 * UI.gs — Card Service builders for the ContextShield add-on.
 *
 * Cards:
 *   buildResultCard()        — main analysis result
 *   buildChatCard()          — persistent conversation thread
 *   buildHistoryDetailCard() — expanded history item
 *   buildErrorCard()         — error state
 */

var SCORE_BAR_LENGTH = 10;

function buildScoreBar(score) {
  var filled = Math.round(score / 10);
  var bar = '';
  for (var i = 0; i < SCORE_BAR_LENGTH; i++) {
    bar += i < filled ? '■' : '□';
  }
  return bar + '  ' + score + '/100';
}

// ---------------------------------------------------------------------------
// Result card
// ---------------------------------------------------------------------------

function buildResultCard(result, messageId, sender, subject) {
  var score = result.score || 0;
  var verdict = result.verdict || 'UNKNOWN';
  var reasoning = result.reasoning || [];
  var signals = result.signals || [];

  var card = CardService.newCardBuilder()
    .setName('contextshield_result')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Email Security Analysis')
    );

  // Score + verdict
  var scoreSection = CardService.newCardSection();
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText(verdict)
  );
  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Risk Score')
      .setText(buildScoreBar(score))
  );
  card.addSection(scoreSection);

  // Reasoning
  if (reasoning.length > 0) {
    var reasonSection = CardService.newCardSection()
      .setHeader('Why')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(2);
    reasoning.forEach(function(line) {
      reasonSection.addWidget(
        CardService.newDecoratedText().setText('• ' + line).setWrapText(true)
      );
    });
    card.addSection(reasonSection);
  }

  // Signals
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

  // Chat input
  var chatSection = CardService.newCardSection().setHeader('Ask the assistant');
  chatSection.addWidget(
    CardService.newTextInput()
      .setFieldName('chat_question')
      .setHint('e.g. Is this link safe? Why is the sender suspicious?')
      .setMultiline(false)
  );
  chatSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText('Ask →')
          .setOnClickAction(CardService.newAction().setFunctionName('onChatSubmit'))
      )
      .addButton(
        CardService.newTextButton()
          .setText('Re-analyze')
          .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
      )
  );
  card.addSection(chatSection);

  // History chips
  var history = getHistory();
  if (history.length > 0) {
    var historySection = CardService.newCardSection()
      .setHeader('Recent')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    history.forEach(function(item) {
      var chip = item.verdict + '  ' + item.score + '/100  ·  ' +
        (item.subject || '(no subject)').substring(0, 30);
      historySection.addWidget(
        CardService.newTextButton()
          .setText(chip)
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName('onHistoryItemClick')
              .setParameters({
                sender: item.sender || '',
                subject: item.subject || '',
                verdict: item.verdict,
                score: String(item.score),
                analyzedAt: item.analyzedAt || '',
              })
          )
      );
    });
    card.addSection(historySection);
  }

  return card.build();
}

// ---------------------------------------------------------------------------
// Persistent chat card
// ---------------------------------------------------------------------------

function buildChatCard(conversation) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_chat')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Security Assistant')
    );

  // Conversation thread
  if (conversation && conversation.length > 0) {
    var threadSection = CardService.newCardSection().setHeader('Conversation');
    conversation.forEach(function(msg) {
      var label = msg.role === 'user' ? 'You' : 'Assistant';
      threadSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(label)
          .setText(msg.content)
          .setWrapText(true)
      );
    });
    card.addSection(threadSection);
  }

  // Next question input
  var inputSection = CardService.newCardSection().setHeader('Continue the conversation');
  inputSection.addWidget(
    CardService.newTextInput()
      .setFieldName('chat_question')
      .setHint('Ask a follow-up question...')
      .setMultiline(false)
  );
  inputSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText('Ask →')
          .setOnClickAction(CardService.newAction().setFunctionName('onChatSubmit'))
      )
      .addButton(
        CardService.newTextButton()
          .setText('Clear chat')
          .setOnClickAction(CardService.newAction().setFunctionName('onClearChat'))
      )
      .addButton(
        CardService.newTextButton()
          .setText('← Back')
          .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
      )
  );
  card.addSection(inputSection);

  return card.build();
}

// ---------------------------------------------------------------------------
// History detail card
// ---------------------------------------------------------------------------

function buildHistoryDetailCard(sender, subject, verdict, score, analyzedAt) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_history_detail')
    .setHeader(
      CardService.newCardHeader()
        .setTitle(verdict + '  ' + score + '/100')
        .setSubtitle('Previous analysis')
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText().setTopLabel('Subject').setText(subject || '(no subject)').setWrapText(true)
  );
  section.addWidget(
    CardService.newDecoratedText().setTopLabel('From').setText(sender || 'Unknown').setWrapText(true)
  );
  if (analyzedAt) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Analyzed at')
        .setText(new Date(analyzedAt).toLocaleString())
    );
  }
  section.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText('← Back')
        .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
    )
  );
  card.addSection(section);
  return card.build();
}

// ---------------------------------------------------------------------------
// Error card
// ---------------------------------------------------------------------------

function buildErrorCard(message) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_error')
    .setHeader(
      CardService.newCardHeader().setTitle('Email Security Analysis')
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText()
      .setText(message || 'Could not reach the analysis service. Please try again.')
      .setWrapText(true)
  );
  section.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText('Retry')
        .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
    )
  );
  card.addSection(section);
  return card.build();
}
