const KEY_PATTERNS = {
  AWS: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
  STRIPE: /(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}/g,
  GITHUB: /gh(p|o|u|s|r)_[a-zA-Z0-9]{36,40}/g,
  GOOGLE: /AIza[0-9A-Za-z\\-_]{35}/g,
  OAUTH: /(?:access_token|refresh_token)[\s:=]["']?(ya29\.[a-zA-Z0-9_-]+|[a-zA-Z0-9]{32,64})["']?/gi,
  JWT: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  FIREBASE: /(?:firebase:)[\s\S]*?["']([a-zA-Z0-9_-]{20,})["']|(?:project_id|api_key|app_id)[\s:=]["']([a-zA-Z0-9_-]{20,})["']/gi,
  SUPABASE: /(?:supabase|anon_key|service_role)[\s:=]["'](sbp?_[a-f0-9]{40})["']/gi,
  PASSWORD: /(?:password|passwd|pwd)[\s:=]["'](.{12,})["']/gi,
  MONGODB: /(?:mongodb(?:\+srv)?:\/\/)[^:]+:([^@]+)@|(?:ObjectId\()?["']([0-9a-f]{24})["']\)?/gi,
  ENCRYPTED: /(?:encrypted|hash|bcrypt)[\s:=]["'](\$2[aby]\$\d+\$[.\/A-Za-z0-9]{53})["']/gi,
  GENERIC: /(?:key|api|token|secret|credential)[\s:=]["']?([0-9a-zA-Z!@#$%^&*()_+\-={};':"\\|,.<>?~]{20,})["']?/gi,
  UUID: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g
};

function calculateEntropy(str) {
  const len = str.length;
  if (len <= 1) return 0;
  
  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  return Object.values(frequencies).reduce((sum, freq) => {
    const p = freq / len;
    return sum - p * Math.log2(p);
  }, 0);
}

function detectKeys(text) {
  const detectedKeys = [];
  
  for (const [service, pattern] of Object.entries(KEY_PATTERNS)) {
    pattern.lastIndex = 0; // Reset regex state
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const keyValue = match[1] || match[0];
      detectedKeys.push({
        service,
        value: keyValue,
        start: match.index,
        end: match.index + keyValue.length,
        entropy: calculateEntropy(keyValue)
      });
    }
  }
  
  const wordRegex = /[a-z0-9!@#$%^&*()_+\-={};':"\\|,.<>?~]{20,}/gi;
  wordRegex.lastIndex = 0;
  let wordMatch;
  while ((wordMatch = wordRegex.exec(text)) !== null) {
    const word = wordMatch[0];
    const entropy = calculateEntropy(word);
    
    if (entropy > 3 && !detectedKeys.some(k => 
        k.start <= wordMatch.index && k.end >= wordMatch.index + word.length)) {
      detectedKeys.push({
        service: 'HIGH_ENTROPY',
        value: word,
        start: wordMatch.index,
        end: wordMatch.index + word.length,
        entropy
      });
    }
  }
  
  return detectedKeys.sort((a, b) => a.start - b.start);
}

function maskKeys(text, keys) {
  if (keys.length === 0) return text;
  
  let maskedText = '';
  let lastIndex = 0;
  
  keys.forEach((key, index) => {
    
    maskedText += text.substring(lastIndex, key.start);
    
    maskedText += `[CHANGED_KEY_${index + 1}_${key.service}]`;
    
    lastIndex = key.end;
  });
  
  maskedText += text.substring(lastIndex);
  
  return maskedText;
}

function createNotification(message, isError = false) {
  const existing = document.querySelector('#key-scan-notification');
  if (existing) existing.remove();
  
  const notification = document.createElement('div');
  notification.id = 'key-scan-notification';
  notification.textContent = message;
  notification.style = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    background: ${isError ? '#ff4757' : '#2ed573'};
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10000;
    font-family: system-ui;
    font-size: 14px;
    transition: opacity 0.3s;
  `;
  
  document.body.appendChild(notification);
  setTimeout(() => notification.style.opacity = '0', 3000);
  setTimeout(() => notification.remove(), 3300);
}

function injectScanButton(micButton) {
  if (!micButton || document.querySelector('#scan-button')) return;
  
  const scanButton = document.createElement('button');
  scanButton.id = 'scan-button';
  scanButton.innerHTML = `
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M15 3H9V5H15V3Z" fill="currentColor"/>
      <path d="M15 19H9V21H15V19Z" fill="currentColor"/>
      <path fill-rule="evenodd" clip-rule="evenodd" d="M3 7V17C3 18.1046 3.89543 19 5 19H7V21H5C3.34315 21 2 19.6569 2 18V6C2 4.34315 3.34315 3 5 3H7V5H5C4.44772 5 4 5.44772 4 6V18C4 18.5523 4.44772 19 5 19H7V7H3Z" fill="currentColor"/>
      <path fill-rule="evenodd" clip-rule="evenodd" d="M19 3H17V5H19C19.5523 5 20 5.44772 20 6V18C20 18.5523 19.5523 19 19 19H17V21H19C20.6569 21 22 19.6569 22 18V6C22 4.34315 20.6569 3 19 3Z" fill="currentColor"/>
      <path d="M8 9H16V15H8V9Z" fill="currentColor"/>
    </svg>
  `;
  scanButton.title = 'Scan for private keys';
  scanButton.ariaLabel = 'Scan for private keys';
  scanButton.className = micButton.className + ' scan-button';
  scanButton.style.cssText = `
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 8px;
  `;
  
  scanButton.onclick = () => {
    const inputDiv = document.querySelector('#prompt-textarea');
    if (!inputDiv) {
      createNotification('Could not find input box!', true);
      return;
    }
    
    const userInput = inputDiv.value || inputDiv.innerText || inputDiv.textContent;
    if (!userInput.trim()) {
      createNotification('Input is empty!', true);
      return;
    }
    
    const keys = detectKeys(userInput);
    if (keys.length === 0) {
      createNotification('No private keys detected');
      return;
    }
    
    const maskedText = maskKeys(userInput, keys);
    
    if (inputDiv.isContentEditable) {
      inputDiv.innerText = maskedText;
    } else {
      inputDiv.value = maskedText;
    }
    
    const event = new Event('input', { bubbles: true });
    inputDiv.dispatchEvent(event);
    
    createNotification(`Masked ${keys.length} potential private keys!`);
    console.log('[Key Scanner] Detected keys:', keys);
  };
  
   micButton.parentElement.insertBefore(scanButton, micButton);
}

function tryInjectWithRetry(retries = 10) {
  const micButton = document.querySelector('button.composer-btn[aria-label="Dictate button"]');
  if (micButton) {
    injectScanButton(micButton);
  } else if (retries > 0) {
    setTimeout(() => tryInjectWithRetry(retries - 1), 500);
  } else {
    console.warn('[Extension] Mic button not found after max retries');
  }
}

function observeForMicButton() {
  const observer = new MutationObserver(() => {
    const micButton = document.querySelector('button.composer-btn[aria-label="Dictate button"]');
    if (micButton) {
      injectScanButton(micButton);
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

observeForMicButton();
tryInjectWithRetry();