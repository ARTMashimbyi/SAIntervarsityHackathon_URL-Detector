URL Guardian - README
📋 Project Overview
URL Guardian is an interactive web application designed to educate users about cybersecurity threats, particularly phishing attacks and malicious URLs. It combines practical tools with educational content to help users identify and avoid online threats.

✨ Features
🔍 URL Validation Tool: Analyze URLs for security risks and potential phishing attempts

🎮 Phishing Detection Game: Test your skills at identifying malicious URLs in a timed game

📚 Learning Center: Educational modules on phishing, social engineering, and secure browsing

📊 User Profile & Progress Tracking: Monitor your learning progress and achievements

🏆 Leaderboard: Compete with others for the highest scores

🛠️ Technologies Used
Frontend: HTML5, CSS3, JavaScript (ES6+)

Icons: Font Awesome 6.4.0

Storage: Local Storage for saving user data

Styling: CSS Grid, Flexbox, CSS Variables

📁 Project Structure
text
src/
├── index.html # Main HTML file
├── style.css # All CSS styles
└── script.js # All JavaScript functionality
🚀 Local Setup
Prerequisites
A modern web browser (Chrome, Firefox, Safari, Edge)

A code editor (VS Code, Sublime Text, etc.)

Live Server extension (for VS Code) or similar local server tool

Installation Steps
Download or clone the project files

bash

# If using git

git clone <https://github.com/ARTMashimbyi/SAIntervarsityHackathon_URL-Detector.git>
cd url-guardian
Organize the files

Place all three files (index.html, style.css, script.js) in the same directory (src folder)

Run with Live Server

If using VS Code, install the "Live Server" extension by Ritwick Dey

Right-click on index.html and select "Open with Live Server"

The application will open in your default browser at http://127.0.0.1:5500/src/index.html

Alternative method: Use Python simple server

bash

# Navigate to the src directory

cd src

🎯 How to Use
URL Checker Tab
Enter a URL in the input field

Click "Analyze URL" to check for security issues

View the results showing whether the URL is safe, suspicious, or invalid

Check your scan history below

Phishing Game Tab
Select a difficulty level (Easy, Medium, Hard)

Click "START GAME"

Identify the phishing URL among the options as quickly as possible

Earn points based on speed and accuracy

Complete all 5 stages to finish the game

Learning Center Tab
Browse through different cybersecurity modules

Click on any module to view detailed educational content

Complete the daily challenge to test your knowledge

Track your progress through module completion indicators

Profile Tab
View your statistics and achievements

Check your weekly activity

See which badges you've earned and which are still locked

🔧 Customization
You can customize the application by:

Modifying CSS variables in the :root section of style.css to change the color scheme

Adding new game levels by extending the gameData object in script.js

Creating new learning modules by adding to the learningContent object

Adjusting validation rules in the validateURL function

📝 Key Functions
validateURL(url) - Analyzes URLs for security issues

checkHomographAttack(hostname) - Detects homograph attacks

calculateSimilarity(str1, str2) - Measures similarity between strings

initGame() - Sets up the phishing detection game

showModule(moduleId) - Displays educational content

saveToLocalStorage() - Persists user data

🌐 Browser Compatibility
This application works on all modern browsers including:

Chrome 60+

Firefox 55+

Safari 12+

Edge 79+

📊 Data Storage
The application uses the browser's Local Storage to save:

User scan history

Game scores and progress

Learning module completion status

User profile information

No data is sent to external servers - everything is stored locally in your browser.

🐛 Troubleshooting
If you encounter issues:

Clear your browser cache if the application doesn't load properly

Check the console (F12) for any JavaScript errors

Ensure all files are in the same directory

Make sure you're using a local server (not opening the HTML file directly)

📄 License
This project is for educational purposes. Feel free to modify and use as needed.

