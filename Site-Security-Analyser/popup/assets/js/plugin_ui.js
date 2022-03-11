var background = chrome.extension.getBackgroundPage();
var colors = {
    "-1": "#58bc8a",
    "0": "#ffeb3c",
    "1": "#ff8b66"
};

chrome.tabs.query({ currentWindow: true, active: true }, function (tabs) {
    var isPhish = background.isPhish[tabs[0].id];
    var legitimatePercent = background.legitimatePercents[tabs[0].id];

    let perc = parseInt(legitimatePercent);
    if (isPhish) {
        $("h2").text("Warning! Suspected Phishing Site");
        $("h2").css("color", '#ed1c23');
        perc = perc - 20;
    }
    const map = (value, x1, y1, x2, y2) => (value - x1) * (y2 - x2) / (y1 - x1) + x2;
    perc = 100 - perc;
    perc = map(perc, 0, 100, -90, 90);
    $(".chart-wrapper .pointer").css('transform', 'rotate(' + perc + 'deg)');
});

