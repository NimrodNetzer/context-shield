/**
 * UI.gs — Card Service builders for the ContextShield add-on.
 *
 * Cards:
 *   buildResultCard()        — main analysis result
 *   buildChatCard()          — full-page persistent chat
 *   buildSignalDetailCard()  — signal tap-to-expand detail
 *   buildHistoryDetailCard() — history item detail
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
    var reasonSection = CardService.newCardSection().setHeader('Why');
    reasoning.forEach(function(line) {
      reasonSection.addWidget(
        CardService.newDecoratedText().setText('• ' + line).setWrapText(true)
      );
    });
    card.addSection(reasonSection);
  }

  // Signals — each one is a tappable chip that opens a detail card
  if (signals.length > 0) {
    var signalSection = CardService.newCardSection()
      .setHeader('Signals  (' + signals.length + ')  — tap to expand');

    signals.forEach(function(signal) {
      var label = signal.type.replace(/_/g, ' ').toUpperCase();
      var chip = '[' + signal.severity.toUpperCase() + ']  ' + label;

      signalSection.addWidget(
        CardService.newTextButton()
          .setText(chip)
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName('onSignalClick')
              .setParameters({
                type: signal.type,
                severity: signal.severity,
                value: signal.value || '',
              })
          )
      );
    });
    card.addSection(signalSection);
  }

  // Action row: Open Chat + Re-analyze
  var actionSection = CardService.newCardSection();
  actionSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText('💬  Ask Assistant')
          .setOnClickAction(CardService.newAction().setFunctionName('onOpenChat'))
      )
      .addButton(
        CardService.newTextButton()
          .setText('↺  Re-analyze')
          .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
      )
  );
  card.addSection(actionSection);

  // History chips
  var history = getHistory();
  if (history.length > 0) {
    var historySection = CardService.newCardSection()
      .setHeader('Recent');

    history.forEach(function(item) {
      var chip = item.verdict + '  ' + item.score + '/100  ·  ' +
        (item.subject || '(no subject)').substring(0, 28);
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
// Chat card — full-page conversation
// ---------------------------------------------------------------------------

function buildChatCard(conversation) {
  var card = CardService.newCardBuilder()
    .setName('contextshield_chat')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Security Assistant')
        .setSubtitle('Ask anything about this email')
    );

  // Add back action to header
  card.addCardAction(
    CardService.newCardAction()
      .setText('← Back to analysis')
      .setOnClickAction(CardService.newAction().setFunctionName('onGmailMessage'))
  );

  // Conversation thread
  if (conversation && conversation.length > 0) {
    var threadSection = CardService.newCardSection()
      .setHeader('Conversation');

    conversation.forEach(function(msg) {
      var label = msg.role === 'user' ? '  You' : '  Assistant';
      threadSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(label)
          .setText(msg.content)
          .setWrapText(true)
      );
    });

    card.addSection(threadSection);
  } else {
    var emptySection = CardService.newCardSection();
    emptySection.addWidget(
      CardService.newDecoratedText()
        .setText('Ask me anything about this email — links, sender identity, suspicious patterns, or what action to take.')
        .setWrapText(true)
    );
    card.addSection(emptySection);
  }

  // Input at bottom
  var inputSection = CardService.newCardSection()
    .setHeader('Message');

  inputSection.addWidget(
    CardService.newTextInput()
      .setFieldName('chat_question')
      .setHint('Type your question...')
      .setMultiline(false)
  );

  inputSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText('Send  →')
          .setOnClickAction(CardService.newAction().setFunctionName('onChatSubmit'))
      )
      .addButton(
        CardService.newTextButton()
          .setText('Clear')
          .setOnClickAction(CardService.newAction().setFunctionName('onClearChat'))
      )
  );

  card.addSection(inputSection);
  return card.build();
}

// ---------------------------------------------------------------------------
// Signal detail card — tapped from result card
// ---------------------------------------------------------------------------

function buildSignalDetailCard(type, severity, value) {
  var descriptions = {
    dkim_fail: 'DKIM signature verification failed. The email\'s cryptographic signature does not match the sender\'s domain, which is a strong indicator of spoofing or tampering.',
    spf_fail: 'SPF check failed. The sending server is not authorized to send email on behalf of this domain. Commonly seen in spoofed emails.',
    dmarc_fail: 'DMARC policy failed. The email failed both SPF and DKIM alignment checks, meaning the domain owner\'s anti-spoofing policy was violated.',
    reply_to_mismatch: 'The Reply-To address is on a different domain than the From address. Attackers use this to receive your replies while appearing to come from a legitimate sender.',
    display_name_spoofing: 'The sender\'s display name contains a known brand name, but the actual email address is from a different domain. A classic phishing technique.',
    homoglyph_domain: 'The sender\'s domain uses characters that visually resemble a known brand\'s domain (e.g. paypa1.com instead of paypal.com).',
    dangerous_attachment: 'The email contains an attachment with a file extension commonly used to deliver malware — executable files, scripts, or macro-enabled documents.',
    suspicious_tld: 'The domain uses a top-level domain (TLD) statistically associated with spam and phishing campaigns.',
    url_shortener: 'The email contains a shortened URL. Attackers use URL shorteners to hide malicious destinations.',
    ip_as_hostname: 'A URL in this email uses a raw IP address instead of a domain name — commonly used to bypass domain-based reputation filters.',
    ssrf_risk_url: 'A URL in this email points to a private or internal IP range. If clicked, it could expose internal network resources.',
    urgency_language: 'The email uses urgency or fear-based language patterns common in phishing — "verify now", "account suspended", "act immediately".',
    safe_browsing_hit: 'This URL was found in Google\'s Safe Browsing database — the same threat intelligence used by Chrome, Firefox, and Safari to block malicious sites.',
  };

  var description = descriptions[type] || 'This signal was flagged as potentially suspicious based on analysis of the email metadata or content.';

  var card = CardService.newCardBuilder()
    .setName('contextshield_signal_detail')
    .setHeader(
      CardService.newCardHeader()
        .setTitle(type.replace(/_/g, ' ').toUpperCase())
        .setSubtitle('Severity: ' + severity.toUpperCase())
    );

  var section = CardService.newCardSection();

  section.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('What this means')
      .setText(description)
      .setWrapText(true)
  );

  if (value) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Detected value')
        .setText(value)
        .setWrapText(true)
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
    .setHeader(CardService.newCardHeader().setTitle('Email Security Analysis'));

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
