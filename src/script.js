// Enhanced URL Validation Functionality
function validateURL(url) {
  try {
    // Basic validation
    if (!url) {
      return {
        isValid: false,
        message: "Please enter a URL",
        details: ["No URL provided"],
      };
    }

    // Check if the URL has a protocol
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      return {
        isValid: false,
        message: "Invalid URL - Missing protocol",
        details: ["URL should start with http:// or https://"],
      };
    }

    // Try to create a URL object (this will throw for invalid URLs)
    const urlObj = new URL(url);

    // Check for valid domain
    const domainParts = urlObj.hostname.split(".");
    if (domainParts.length < 2 || domainParts.some((part) => !part)) {
      return {
        isValid: false,
        message: "Invalid domain name",
        details: ["The domain name appears to be malformed"],
      };
    }

    // Check for suspicious patterns (phishing detection)
    const suspiciousPatterns = [
      {
        pattern:
          /https?:\/\/(?!www\.)(.*\.)?(paypal|ebay|amazon|bankofamerica|wellsfargo|chase)\./,
        message: "Suspicious domain mimicking known brand",
      },
      {
        pattern: /@/,
        message: "URL contains '@' character - often used in phishing attempts",
      },
      {
        pattern: /\.(tk|ml|ga|cf|gq)$/,
        message:
          "URL uses free domain extension often associated with malicious sites",
      },
      {
        pattern: /https?:\/\/[^\/]+\/login\.php/,
        message: "Generic login page - could be phishing",
      },
      {
        pattern: /https?:\/\/[^\/]+\/[a-f0-9]{16,}/,
        message: "Long hexadecimal strings in path - could be obfuscation",
      },
    ];

    const detectedPatterns = [];
    for (const { pattern, message } of suspiciousPatterns) {
      if (pattern.test(url)) {
        detectedPatterns.push(message);
      }
    }

    // If suspicious patterns detected
    if (detectedPatterns.length > 0) {
      return {
        isValid: false,
        message: "Potential phishing URL detected",
        details: detectedPatterns,
        isSuspicious: true,
      };
    }

    // If all checks pass
    return {
      isValid: true,
      message: "This URL appears to be valid and safe",
      parsedURL: {
        protocol: urlObj.protocol,
        host: urlObj.host,
        hostname: urlObj.hostname,
        pathname: urlObj.pathname,
        search: urlObj.search,
        hash: urlObj.hash,
      },
    };
  } catch (error) {
    return {
      isValid: false,
      message: "Invalid URL format",
      details: [error.toString()],
    };
  }
}

// Game data
const gameData = {
  easy: [
    {
      valid: [
        "https://www.google.com",
        "https://www.github.com",
        "https://stackoverflow.com",
      ],
      invalid: "htt://www.invalid.com",
      explanation:
        "The invalid URL uses 'htt://' instead of 'http://' or 'https://'",
    },
    {
      valid: [
        "https://www.wikipedia.org",
        "https://www.reddit.com",
        "https://www.linkedin.com",
      ],
      invalid: "https://www.invalid.123",
      explanation:
        "The invalid URL uses '.123' which is not a valid top-level domain",
    },
    {
      valid: [
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.ebay.com",
      ],
      invalid: "https://www.invalid-.com",
      explanation:
        "The invalid URL contains a hyphen at the end of the subdomain",
    },
    {
      valid: [
        "https://www.twitter.com",
        "https://www.instagram.com",
        "https://www.pinterest.com",
      ],
      invalid: "https://www.invalid space.com",
      explanation:
        "The invalid URL contains a space which is not allowed in URLs",
    },
    {
      valid: [
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.adobe.com",
      ],
      invalid: "https://www.invalid@character.com",
      explanation:
        "The invalid URL contains an '@' character outside of the userinfo section",
    },
  ],
  medium: [
    {
      valid: [
        "https://sub.domain.com/path",
        "https://example.com:8080/page",
        "https://user:pass@example.com",
      ],
      invalid: "https://..example.com",
      explanation: "The invalid URL contains consecutive dots in the domain",
    },
    {
      valid: [
        "https://example.com/?query=value",
        "https://example.com/#fragment",
        "https://example.com/path/to/page",
      ],
      invalid: "https://example.com/../invalid",
      explanation:
        "The invalid URL uses '..' to traverse directories which can be suspicious",
    },
    {
      valid: ["https://example.com", "http://example.com", "ftp://example.com"],
      invalid: "https://example.com:65536",
      explanation:
        "The invalid URL uses port 65536 which is outside the valid port range (0-65535)",
    },
    {
      valid: [
        "https://example.com",
        "https://192.168.1.1",
        "https://localhost:3000",
      ],
      invalid: "https://256.256.256.256",
      explanation:
        "The invalid URL uses an IP address with octets outside the valid range (0-255)",
    },
    {
      valid: [
        "https://example.com",
        "https://www.example.co.uk",
        "https://sub.sub.example.com",
      ],
      invalid: "https://example.-com.com",
      explanation:
        "The invalid URL contains a hyphen at the beginning of a domain part",
    },
  ],
  hard: [
    {
      valid: [
        "https://example.com/测试",
        "https://example.com/🦄",
        "https://пример.тест",
      ],
      invalid: "https://example.com/\\x00",
      explanation:
        "The invalid URL contains a null character which can be used in injection attacks",
    },
    {
      valid: [
        "https://example.com",
        "https://xn--example-8g0a.com",
        "https://example.com/?a=1&b=2",
      ],
      invalid: "https://example.com/?a=script>alert('xss')</script",
      explanation: "The invalid URL contains potential XSS attack code",
    },
    {
      valid: [
        "https://example.com",
        "https://1.2.3.4",
        "https://[2001:db8::1]",
      ],
      invalid: "https://[2001:db8:::1]",
      explanation:
        "The invalid URL contains an invalid IPv6 address with consecutive colons",
    },
    {
      valid: [
        "https://example.com",
        "https://example.com:65535",
        "https://example.com:0",
      ],
      invalid: "https://example.com:99999",
      explanation: "The invalid URL uses a port number outside the valid range",
    },
    {
      valid: [
        "https://example.com",
        "https://example.com/very/long/path/that/is/valid",
        "https://example.com/?very=long&query=string&with=many=parameters",
      ],
      invalid: "https://example.com/" + "a".repeat(10000),
      explanation:
        "The invalid URL is excessively long which can be used in buffer overflow attacks",
    },
  ],
};

// Learning module content
const learningContent = {
  phishing: {
    title: "Phishing Awareness",
    content: `
            <h2>Understanding Phishing Attacks</h2>
            <p>Phishing is a cybercrime in which targets are contacted by email, telephone, or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as personally identifiable information, banking and credit card details, and passwords.</p>
            
            <h3>Common Phishing Techniques</h3>
            <ul>
                <li><strong>Email Phishing:</strong> Fraudulent emails that appear to be from legitimate sources</li>
                <li><strong>Spear Phishing:</strong> Targeted attacks on specific individuals or organizations</li>
                <li><strong>Whaling:</strong> Attacks targeting high-profile executives</li>
                <li><strong>Smishing:</strong> Phishing via SMS text messages</li>
                <li><strong>Vishing:</strong> Phishing via voice calls</li>
            </ul>
            
            <h3>How to Identify Phishing Attempts</h3>
            <ul>
                <li>Check for spelling mistakes and poor grammar</li>
                <li>Look for generic greetings instead of personalized ones</li>
                <li>Hover over links to see the actual URL before clicking</li>
                <li>Be wary of urgent or threatening language</li>
                <li>Check the sender's email address carefully</li>
            </ul>
            
            <h3>Protecting Yourself</h3>
            <ul>
                <li>Never provide personal information via email or text</li>
                <li>Use two-factor authentication whenever possible</li>
                <li>Keep your software and browsers updated</li>
                <li>Use anti-phishing browser extensions</li>
                <li>Report suspected phishing attempts to your IT department</li>
            </ul>
        `,
  },
  social: {
    title: "Social Engineering",
    content: `
            <h2>Understanding Social Engineering</h2>
            <p>Social engineering is the psychological manipulation of people into performing actions or divulging confidential information. It differs from traditional hacking as it relies on human interaction and often involves tricking people into breaking normal security procedures.</p>
            
            <h3>Common Social Engineering Techniques</h3>
            <ul>
                <li><strong>Pretexting:</strong> Creating a fabricated scenario to engage a targeted victim</li>
                <li><strong>Baiting:</strong> Offering something enticing to lure victims</li>
                <li><strong>Quid Pro Quo:</strong> Offering a benefit in exchange for information</li>
                <li><strong>Tailgating:</strong> Gaining physical access to restricted areas by following authorized personnel</li>
                <li><strong>Phishing:</strong> Using fake communications to extract sensitive data</li>
            </ul>
            
            <h3>How to Recognize Social Engineering Attacks</h3>
            <ul>
                <li>Requests for sensitive information via email or phone</li>
                <li>Urgent or threatening language designed to prompt quick action</li>
                <li>Offers that seem too good to be true</li>
                <li>Requests to bypass normal security protocols</li>
                <li>Unsolicited requests for help from "IT support" or "service providers"</li>
            </ul>
            
            <h3>Protection Strategies</h3>
            <ul>
                <li>Verify the identity of anyone requesting sensitive information</li>
                <li>Be cautious of unsolicited requests, even if they appear to be from known contacts</li>
                <li>Implement multi-factor authentication for all sensitive systems</li>
                <li>Regularly train employees to recognize social engineering tactics</li>
                <li>Establish clear protocols for handling sensitive information requests</li>
            </ul>
        `,
  },
  browsing: {
    title: "Secure Browsing",
    content: `
            <h2>Secure Web Browsing Practices</h2>
            <p>Secure browsing involves taking precautions to protect your personal information and computer from online threats while using the internet. This includes being aware of potential risks and implementing protective measures.</p>
            
            <h3>Essential Secure Browsing Practices</h3>
            <ul>
                <li><strong>Use HTTPS:</strong> Always look for the padlock icon and "https://" in the address bar</li>
                <li><strong>Keep Software Updated:</strong> Regularly update your browser and plugins</li>
                <li><strong>Use Strong Passwords:</strong> Create unique, complex passwords for different sites</li>
                <li><strong>Enable Two-Factor Authentication:</strong> Add an extra layer of security to your accounts</li>
                <li><strong>Be Cautious with Downloads:</strong> Only download files from trusted sources</li>
            </ul>
            
            <h3>Browser Security Settings</h3>
            <ul>
                <li>Enable phishing and malware protection in your browser settings</li>
                <li>Clear browsing data regularly, especially cookies and cache</li>
                <li>Use private browsing mode when accessing sensitive information on shared devices</li>
                <li>Disable auto-fill for forms and passwords on public computers</li>
                <li>Review and adjust privacy settings to limit data sharing</li>
            </ul>
            
            <h3>Recognizing Secure Websites</h3>
            <ul>
                <li>Look for the padlock icon in the address bar</li>
                <li>Check that the URL begins with "https://" rather than "http://"</li>
                <li>Verify the website's security certificate if prompted by your browser</li>
                <li>Be wary of sites with numerous pop-ups or redirects</li>
                <li>Check for legitimate contact information and privacy policies</li>
            </ul>
            
            <h3>Additional Security Measures</h3>
            <ul>
                <li>Use a reputable antivirus and anti-malware solution</li>
                <li>Consider using a VPN, especially on public Wi-Fi networks</li>
                <li>Install browser extensions that block ads and trackers</li>
                <li>Regularly review browser extensions and remove any you don't use</li>
                <li>Educate yourself about current online threats and scams</li>
            </ul>
        `,
  },
};

// Application state
let appState = {
  currentTab: "checker",
  scanHistory: [],
  gameState: {
    difficulty: "easy",
    currentStage: 0,
    score: 0,
    startTime: 0,
    timerInterval: null,
    currentTime: 0,
  },
  userProfile: {
    username: "Cyber Defender",
    level: 5,
    streak: 12,
    accuracy: 85,
    scans: 47,
    games: 36,
    successRate: 92,
    badges: ["first-scan", "phishing-expert"],
  },
};

// DOM elements
const navLinks = document.querySelectorAll(".nav-link");
const tabContents = document.querySelectorAll(".tab-content");
const urlInput = document.getElementById("url-input");
const validateBtn = document.getElementById("validate-btn");
const validationResult = document.getElementById("validation-result");
const scanHistoryElement = document.getElementById("scan-history");
const startScreen = document.getElementById("game-area");
const startBtn = document.getElementById("start-btn");
const restartBtn = document.getElementById("restart-btn");
const nextBtn = document.getElementById("next-btn");
const scoreElement = document.getElementById("score");
const levelElement = document.getElementById("level");
const stageElement = document.getElementById("stage");
const urlContainer = document.getElementById("url-container");
const resultElement = document.getElementById("result");
const timerElement = document.getElementById("timer");
const progressElement = document.getElementById("progress");
const difficultyBtns = document.querySelectorAll(".difficulty-btn");
const notification = document.getElementById("notification");
const modules = document.querySelectorAll(".module");
const moduleContent = document.getElementById("module-content");
const moduleDetails = document.getElementById("module-details");
const backToModules = document.getElementById("back-to-modules");
const dailyChallengeBtn = document.getElementById("daily-challenge-btn");

// Initialize application
function initApp() {
  // Load data from localStorage
  loadFromLocalStorage();

  // Set up event listeners for navigation
  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = link.dataset.tab;

      // Update active nav link
      navLinks.forEach((l) => l.classList.remove("active"));
      link.classList.add("active");

      // Show corresponding tab
      tabContents.forEach((content) => content.classList.remove("active"));
      document.getElementById(tab).classList.add("active");

      // Update app state
      appState.currentTab = tab;

      // Save to localStorage
      saveToLocalStorage();
    });
  });

  // Set up URL validation
  validateBtn.addEventListener("click", validateUrl);
  urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") validateUrl();
  });

  // Set up game
  initGame();

  // Set up learning modules
  modules.forEach((module) => {
    module.addEventListener("click", () => {
      const moduleId = module.dataset.module;
      showModule(moduleId);
    });
  });

  backToModules.addEventListener("click", hideModule);

  // Set up daily challenge
  dailyChallengeBtn.addEventListener("click", handleDailyChallenge);

  // Load initial data
  loadScanHistory();
  updateLeaderboard();

  // Show welcome notification
  showNotification(
    "Welcome to URL Guardian! Start by checking a URL or playing the game.",
    "info"
  );
}

// Load data from localStorage
function loadFromLocalStorage() {
  const savedData = localStorage.getItem("urlGuardianData");
  if (savedData) {
    const parsedData = JSON.parse(savedData);
    appState.scanHistory = parsedData.scanHistory || [];
    appState.userProfile = parsedData.userProfile || appState.userProfile;

    // Update UI with loaded data
    updateProfileUI();
  }
}

// Save data to localStorage
function saveToLocalStorage() {
  const dataToSave = {
    scanHistory: appState.scanHistory,
    userProfile: appState.userProfile,
  };
  localStorage.setItem("urlGuardianData", JSON.stringify(dataToSave));
}

// Update profile UI with current data
function updateProfileUI() {
  // This would update various profile elements with data from appState.userProfile
  // Implementation would depend on what specific elements need updating
}

// Validate URL function
function validateUrl() {
  const url = urlInput.value.trim();
  if (!url) return;

  const result = validateURL(url);
  showValidationResult(result);

  // Add to history
  addToScanHistory(url, result);

  // Update UI
  loadScanHistory();

  // Show notification
  if (result.isValid && !result.isSuspicious) {
    showNotification("URL is valid and safe!", "success");
  } else if (result.isSuspicious) {
    showNotification("Warning: Potential phishing URL detected!", "error");
  } else {
    showNotification("URL is invalid.", "error");
  }

  // Save to localStorage
  saveToLocalStorage();
}

// Show validation result
function showValidationResult(result) {
  validationResult.className = "result-box";
  validationResult.classList.add(
    result.isValid && !result.isSuspicious ? "valid" : "invalid"
  );
  validationResult.classList.remove("hidden");

  validationResult.innerHTML = `
        <div class="result-icon">
            <i class="fas ${
              result.isValid && !result.isSuspicious
                ? "fa-check-circle"
                : "fa-exclamation-triangle"
            }"></i>
        </div>
        <div class="result-text">
            <h4>${
              result.isValid && !result.isSuspicious
                ? "Valid URL"
                : result.isSuspicious
                ? "Suspicious URL"
                : "Invalid URL"
            }</h4>
            <p>${result.message}</p>
            ${
              result.details
                ? `
                <ul>
                    ${result.details
                      .map((detail) => `<li>${detail}</li>`)
                      .join("")}
                </ul>
            `
                : ""
            }
            ${
              result.parsedURL
                ? `
                <div class="url-details">
                    <p><strong>Protocol:</strong> ${
                      result.parsedURL.protocol
                    }</p>
                    <p><strong>Host:</strong> ${result.parsedURL.host}</p>
                    <p><strong>Path:</strong> ${
                      result.parsedURL.pathname || "/"
                    }</p>
                </div>
            `
                : ""
            }
        </div>
    `;
}

// Add URL to scan history
function addToScanHistory(url, result) {
  appState.scanHistory.unshift({
    url,
    timestamp: new Date(),
    result,
  });

  // Keep only last 10 scans
  if (appState.scanHistory.length > 10) {
    appState.scanHistory.pop();
  }

  // Update user profile
  appState.userProfile.scans++;
}

// Load scan history
function loadScanHistory() {
  // Add some mock scans if history is empty
  if (appState.scanHistory.length === 0) {
    appState.scanHistory = [
      {
        url: "https://www.paypal.com.login.security.verify.com",
        timestamp: new Date(Date.now() - 86400000), // 1 day ago
        result: {
          isValid: false,
          message: "Potential phishing URL detected",
          details: ["Suspicious domain mimicking known brand"],
          isSuspicious: true,
        },
      },
      {
        url: "https://www.github.com",
        timestamp: new Date(Date.now() - 172800000), // 2 days ago
        result: {
          isValid: true,
          message: "This URL appears to be valid and safe",
          parsedURL: {
            protocol: "https:",
            host: "www.github.com",
            hostname: "www.github.com",
            pathname: "/",
            search: "",
            hash: "",
          },
        },
      },
      {
        url: "https://secure-apple-id.verify.com",
        timestamp: new Date(Date.now() - 259200000), // 3 days ago
        result: {
          isValid: false,
          message: "Potential phishing URL detected",
          details: ["Suspicious domain mimicking known brand"],
          isSuspicious: true,
        },
      },
    ];
  }

  scanHistoryElement.innerHTML = "";
  appState.scanHistory.forEach((scan) => {
    const scanElement = document.createElement("div");
    scanElement.className = "result-box";
    scanElement.classList.add(
      scan.result.isValid && !scan.result.isSuspicious ? "valid" : "invalid"
    );
    scanElement.style.marginBottom = "10px";
    scanElement.style.padding = "10px";

    scanElement.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="font-weight: bold; max-width: 70%; overflow: hidden; text-overflow: ellipsis;">${
                  scan.url
                }</div>
                <div style="font-size: 0.9rem; color: #7f8c8d;">${formatTime(
                  scan.timestamp
                )}</div>
            </div>
        `;

    scanHistoryElement.appendChild(scanElement);
  });
}

// Format time for display
function formatTime(date) {
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// Show notification
function showNotification(message, type) {
  notification.textContent = message;
  notification.className = `notification ${type}`;
  notification.classList.add("show");

  setTimeout(() => {
    notification.classList.remove("show");
  }, 3000);
}

// Update leaderboard
function updateLeaderboard() {
  const leaderboardBody = document.getElementById("leaderboard-body");
  // For demo purposes, we'll use mock data
  const mockData = [
    { name: "CyberHero", level: "Hard", score: 12500 },
    { name: "URLMaster", level: "Medium", score: 9800 },
    { name: "PhishBuster", level: "Hard", score: 15200 },
    { name: "SecureSam", level: "Easy", score: 7200 },
    { name: "You", level: "Medium", score: 6400 },
  ];

  leaderboardBody.innerHTML = "";
  mockData.forEach((player) => {
    const row = document.createElement("tr");
    row.style.borderBottom = "1px solid #eee";
    row.innerHTML = `
            <td style="padding: 10px;">${player.name}</td>
            <td style="text-align: center; padding: 10px;">${player.level}</td>
            <td style="text-align: right; padding: 10px;">${player.score.toLocaleString()}</td>
        `;
    leaderboardBody.appendChild(row);
  });
}

// Initialize game
function initGame() {
  // Set up event listeners
  startBtn.addEventListener("click", startGame);
  restartBtn.addEventListener("click", restartGame);
  nextBtn.addEventListener("click", nextStage);

  // Set up difficulty buttons
  difficultyBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      difficultyBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      appState.gameState.difficulty = btn.dataset.difficulty;

      // Save to localStorage
      saveToLocalStorage();
    });
  });
}

// Start the game
function startGame() {
  startBtn.classList.add("hidden");
  document.querySelector(".difficulty-btns").classList.add("hidden");
  startScreen.classList.remove("hidden");

  appState.gameState.currentStage = 0;
  appState.gameState.score = 0;
  updateUI();

  loadStage();
}

// Load current stage
function loadStage() {
  const stageData =
    gameData[appState.gameState.difficulty][appState.gameState.currentStage];
  const allUrls = [...stageData.valid, stageData.invalid];

  // Shuffle URLs
  shuffleArray(allUrls);

  // Clear URL container
  urlContainer.innerHTML = "";

  // Create URL options
  allUrls.forEach((url) => {
    const urlElement = document.createElement("div");
    urlElement.classList.add("url-option");
    urlElement.textContent = url;
    urlElement.addEventListener("click", () =>
      checkAnswer(url, urlElement, stageData.explanation)
    );
    urlContainer.appendChild(urlElement);
  });

  // Start timer
  startTimer();

  // Reset result
  resultElement.textContent = "";
  resultElement.className = "result";

  // Hide next button
  nextBtn.classList.add("hidden");
}

// Check if answer is correct
function checkAnswer(url, element, explanation) {
  const stageData =
    gameData[appState.gameState.difficulty][appState.gameState.currentStage];
  const isInvalid = url === stageData.invalid;

  // Stop timer
  stopTimer();

  if (isInvalid) {
    // Correct answer
    const timeTaken = appState.gameState.currentTime;
    const points = calculatePoints(timeTaken);
    appState.gameState.score += points;

    element.style.borderColor = "var(--success)";
    element.style.background = "#e8f5e9";
    resultElement.innerHTML = `Correct! +${points} points<br><small>${explanation}</small>`;
    resultElement.className = "result correct";

    // Update user profile
    appState.userProfile.games++;
  } else {
    // Incorrect answer
    element.style.borderColor = "var(--danger)";
    element.style.background = "#ffebee";

    // Highlight the correct answer
    const urlElements = document.querySelectorAll(".url-option");
    urlElements.forEach((el) => {
      if (el.textContent === stageData.invalid) {
        el.style.borderColor = "var(--success)";
        el.style.background = "#e8f5e9";
      }
    });

    resultElement.innerHTML = `Incorrect!<br><small>${explanation}</small>`;
    resultElement.className = "result incorrect";
  }

  // Show next button or finish game
  if (appState.gameState.currentStage < 4) {
    nextBtn.classList.remove("hidden");
  } else {
    nextBtn.textContent = "See Results";
    nextBtn.classList.remove("hidden");
  }

  updateUI();
  updateLeaderboard();

  // Save to localStorage
  saveToLocalStorage();
}

// Calculate points based on time taken
function calculatePoints(timeTaken) {
  const maxPoints = 1000;
  let points = Math.max(maxPoints - timeTaken * 20, 100);

  // Adjust points based on difficulty
  if (appState.gameState.difficulty === "medium") points *= 1.5;
  if (appState.gameState.difficulty === "hard") points *= 2;

  return Math.round(points);
}

// Move to next stage
function nextStage() {
  if (appState.gameState.currentStage < 4) {
    appState.gameState.currentStage++;
    loadStage();
  } else {
    // Game finished
    resultElement.textContent = `Game Over! Final Score: ${appState.gameState.score}`;
    resultElement.className = "result";
    nextBtn.classList.add("hidden");

    // Disable URL options
    const urlElements = document.querySelectorAll(".url-option");
    urlElements.forEach((el) => {
      el.style.pointerEvents = "none";
    });

    // Show notification
    showNotification(
      `Congratulations! You scored ${appState.gameState.score} points.`,
      "success"
    );
  }

  // Save to localStorage
  saveToLocalStorage();
}

// Restart game
function restartGame() {
  stopTimer();
  startScreen.classList.add("hidden");
  document.querySelector(".difficulty-btns").classList.remove("hidden");
  startBtn.classList.remove("hidden");
}

// Start timer
function startTimer() {
  appState.gameState.startTime = Date.now();
  appState.gameState.currentTime = 0;
  timerElement.textContent = "0";

  if (appState.gameState.timerInterval)
    clearInterval(appState.gameState.timerInterval);

  appState.gameState.timerInterval = setInterval(() => {
    appState.gameState.currentTime =
      (Date.now() - appState.gameState.startTime) / 1000;
    timerElement.textContent = appState.gameState.currentTime.toFixed(1);

    // Update progress bar (max 15 seconds per question)
    const progressPercent = Math.min(
      (appState.gameState.currentTime / 15) * 100,
      100
    );
    progressElement.style.width = `${progressPercent}%`;

    // Change color when time is running out
    if (appState.gameState.currentTime > 10) {
      progressElement.style.background = "var(--danger)";
    } else if (appState.gameState.currentTime > 5) {
      progressElement.style.background = "var(--warning)";
    }
  }, 100);
}

// Stop timer
function stopTimer() {
  if (appState.gameState.timerInterval) {
    clearInterval(appState.gameState.timerInterval);
    appState.gameState.timerInterval = null;
  }
}

// Update UI elements
function updateUI() {
  scoreElement.textContent = appState.gameState.score;
  levelElement.textContent =
    appState.gameState.difficulty.charAt(0).toUpperCase() +
    appState.gameState.difficulty.slice(1);
  stageElement.textContent = `${appState.gameState.currentStage + 1}/5`;
}

// Utility function to shuffle array
function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// Show learning module
function showModule(moduleId) {
  const content = learningContent[moduleId];
  if (!content) return;

  // Hide modules and show content
  document.querySelector(".learning-modules").classList.add("hidden");
  document.getElementById("daily-challenge").classList.add("hidden");
  moduleContent.classList.remove("hidden");

  // Set module content
  moduleDetails.innerHTML = `
        <h2>${content.title}</h2>
        <div class="learning-content">
            ${content.content}
        </div>
    `;

  // Update progress for this module
  const progressElement = document.querySelector(
    `.module[data-module="${moduleId}"] .module-progress`
  );
  if (progressElement) {
    const currentWidth = parseInt(progressElement.style.width);
    if (currentWidth < 100) {
      progressElement.style.width = `${currentWidth + 25}%`;
    }
  }

  // Save to localStorage
  saveToLocalStorage();
}

// Hide learning module
function hideModule() {
  moduleContent.classList.add("hidden");
  document.querySelector(".learning-modules").classList.remove("hidden");
  document.getElementById("daily-challenge").classList.remove("hidden");
}

// Handle daily challenge
function handleDailyChallenge() {
  const urlOptions = document.querySelectorAll("#daily-challenge .url-option");
  let selectedUrl = null;

  urlOptions.forEach((option) => {
    if (option.classList.contains("selected")) {
      selectedUrl = option.textContent;
    }

    option.addEventListener("click", () => {
      urlOptions.forEach((o) => o.classList.remove("selected"));
      option.classList.add("selected");
    });
  });

  if (!selectedUrl) {
    showNotification("Please select a URL first.", "error");
    return;
  }

  // Check if the answer is correct (first URL is the phishing one)
  if (selectedUrl === "https://secure-paypal.com/login") {
    showNotification(
      "Correct! This is a phishing URL that mimics the real PayPal site.",
      "success"
    );

    // Update user profile
    appState.userProfile.streak++;
    if (appState.userProfile.streak > appState.userProfile.bestStreak) {
      appState.userProfile.bestStreak = appState.userProfile.streak;
    }
  } else {
    showNotification(
      'Incorrect. The phishing URL is "https://secure-paypal.com/login".',
      "error"
    );
    appState.userProfile.streak = 0;
  }

  // Save to localStorage
  saveToLocalStorage();
}

// Initialize the application when page loads
window.addEventListener("load", initApp);
