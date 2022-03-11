const ip2whoisApiKey = "EO2SSEARIRGYZ2NQC2ISCEWMDPL7PSQ5";

var results = {};
var legitimatePercents = {};
var isPhish = {};

// Colors for indicating risk status.
const colors = [
  '#039da2',
  '#2bb274',
  '#8cc640',
  '#d4dd21',
  '#fceb2e',
  '#f5921d',
  '#ef5b29',
  '#ed1c23'
]

// Map range function for converting percentage to -+90 rotating degree.
// @source https://gist.github.com/xposedbones/75ebaef3c10060a3ee3b246166caab56
const map = (value, x1, y1, x2, y2) => (value - x1) * (y2 - x2) / (y1 - x1) + x2;

function fetchLive(callback) {
  $.getJSON(chrome.runtime.getURL('') + "data/classifier.json", function (data) {
    chrome.storage.local.set({ cache: data, cacheTime: Date.now() }, function () {
      callback(data);
    });
  });
}

function fetchCLF(callback) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['cache', 'cacheTime'], function (items) {
      if (items.cache && items.cacheTime) {
        resolve(callback(items.cache));
      }
      fetchLive(callback);
      resolve(true);
    });
  });
}

// Return age value as promise
function getDomainAge(domain) {
  return new Promise((resolve, reject) => {
    setTimeout(function () {
      reject(new Error("timeout"))
    }, 3000);
    fetch('https://api.ip2whois.com/v2?key=' + ip2whoisApiKey + '&domain=' + domain).then(data => data.json().then(json => resolve(json.domain_age)).catch(err => reject(err)));
  });
}

// Return rank value as promise
function getDomainRank(domain) {
  return new Promise((resolve, reject) => {
    setTimeout(function () {
      reject(new Error("timeout"))
    }, 3000);
    fetch('http://data.alexa.com/data?cli=10&url=' + domain).then(data => data.text().then(text => resolve(text.match(/<REACH RANK="(\d+)"\/>/)[1]))).catch(err => reject(err));
  });
}

async function classify(tabId, result, domain) {
  var legitimateCount = 0;
  var suspiciousCount = 0;
  var phishingCount = 0;

  // Get domain age and calculate.
  try {
    var domainAge = await getDomainAge(domain);
  } catch (error) {
    var domainAge = 5;
  }
  result['domainAge'] = domainAge > 8 ? "-1" : (domainAge > 3 ? "0" : "1");

  // Get domain Rank and calculate
  try {
    var domainRank = await getDomainRank(domain);
  } catch (error) {
    var domainRank = 50000;
  }
  result['domainRank'] = domainRank < 10000 ? "-1" : (domainRank < 100000 ? "0" : "1");

  for (var key in result) {
    if (result[key] == "1") phishingCount++;
    else if (result[key] == "0") suspiciousCount++;
    else legitimateCount++;
  }

  legitimatePercents[tabId] = legitimateCount / (phishingCount + suspiciousCount + legitimateCount) * 100;

  if (result.length != 0) {
    var X = [];
    X[0] = [];
    for (var key in result) {
      X[0].push(parseInt(result[key]));
    }

    await fetchCLF(function (clf) {
      var rf = random_forest(clf);
      y = rf.predict(X);
      if (y[0][0]) {
        // Baypass phising algoritm for first 1000 sites.
        if (domainRank > 1000) {
          isPhish[tabId] = true;
          chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            chrome.tabs.sendMessage(tabs[0].id, { action: "notify" });
          });
        } else {
          isPhish[tabId] = false;
        }
      } else {
        isPhish[tabId] = false;
      }
    });
  }

  if (isPhish[tabId]) {
    chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: colors[7] }, () => {
      chrome.browserAction.setBadgeText({ tabId: tabId, text: ' ' });
    });
  } else {
    chrome.browserAction.setBadgeBackgroundColor({ tabId: tabId, color: colors[Math.round(map(100 - legitimatePercents[tabId], 0, 100, 0, 7))] }, () => {
      chrome.browserAction.setBadgeText({ tabId: tabId, text: ' ' });
    });
  }
}

chrome.runtime.onMessage.addListener(async function (request, sender, sendResponse) {
  var domain = sender.origin.replace('https://', '').replace('http://', '').replace('www.', '');
  results[sender.tab.id] = request;
  classify(sender.tab.id, request, domain);
  sendResponse({ received: "result" });
});
