const PHISHING_DETECTOR = {
    result: {},
    url: null,
    urlDomain: null,
    onlyDomain: null,
    init: function () {
        this.url = window.location.href;
        this.urlDomain = window.location.hostname;
        this.onlyDomain = this.urlDomain.replace('www.', '');

        // IP Address feature's function
        const f1 = () => {
            var pattern = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
            var pattern2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
            var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

            if (ip.test(this.urlDomain) || pattern.test(this.urlDomain) || pattern2.test(this.urlDomain)) {
                this.result["IP Address"] = "1";
            } else {
                this.result["IP Address"] = "-1";
            }
        };

        // URL Length feature's function
        const f2 = () => {
            if (this.url.length < 54) {
                this.result["URL Length"] = "-1";
            } else if (this.url.length >= 54 && this.url.length <= 75) {
                this.result["URL Length"] = "0";
            } else {
                this.result["URL Length"] = "1";
            }
        }

        // Tiny URL feature's function
        const f3 = () => {
            if (this.onlyDomain.length < 7) {
                this.result["Tiny URL"] = "1";
            } else {
                this.result["Tiny URL"] = "-1";
            }
        }

        // @ Symbol feature's function
        const f4 = () => {
            pattern = /@/;
            if (pattern.test(this.url)) {
                this.result["@ Symbol"] = "1";
            } else {
                this.result["@ Symbol"] = "-1";
            }

        }

        // Redirecting using // feature's function
        const f5 = () => {
            if (this.url.lastIndexOf("//") > 7) {
                this.result["Redirecting using //"] = "1";
            } else {
                this.result["Redirecting using //"] = "-1";
            }

        }

        // (-) Prefix/Suffix in domain feature's function
        const f6 = () => {
            pattern = /-/;
            if (pattern.test(this.urlDomain)) {
                this.result["(-) Prefix/Suffix in domain"] = "1";
            } else {
                this.result["(-) Prefix/Suffix in domain"] = "-1";
            }

        }

        // No. of Sub Domains feature's function
        const f7 = () => {
            if ((this.onlyDomain.match(RegExp('\\.', 'g')) || []).length == 1) {
                this.result["No. of Sub Domains"] = "-1";
            } else if ((this.onlyDomain.match(RegExp('\\.', 'g')) || []).length == 2) {
                this.result["No. of Sub Domains"] = "0";
            } else {
                this.result["No. of Sub Domains"] = "1";
            }

        }

        // HTTPS feature's function
        const f8 = () => {
            pattern = /https:\/\//;
            if (pattern.test(this.url)) {
                this.result["HTTPS"] = "-1";
            } else {
                this.result["HTTPS"] = "1";
            }

        }

        // Favicon feature's function
        const f9 = () => {
            var favicon = undefined;
            var nodeList = document.getElementsByTagName("link");
            for (var i = 0; i < nodeList.length; i++) {
                if ((nodeList[i].getAttribute("rel") == "icon") || (nodeList[i].getAttribute("rel") == "shortcut icon")) {
                    favicon = nodeList[i].getAttribute("href");
                }
            }
            if (!favicon) {
                this.result["Favicon"] = "-1";
            } else if (favicon.length == 12) {
                this.result["Favicon"] = "-1";
            } else {
                pattern = RegExp(this.urlDomain, 'g');
                if (pattern.test(favicon)) {
                    this.result["Favicon"] = "-1";
                } else {
                    this.result["Favicon"] = "1";
                }
            }
        }

        // Using Non-Standard Port feature's function
        const f10 = () => {
            this.result["Port"] = "-1";

        }

        // HTTPS in URL's domain part feature's function
        const f11 = () => {
            pattern = /https/;
            if (pattern.test(this.onlyDomain)) {
                this.result["HTTPS in URL's domain part"] = "1";
            } else {
                this.result["HTTPS in URL's domain part"] = "-1";
            }
        }

        // Request URL feature's function
        const f12 = () => {
            var imgTags = document.getElementsByTagName("img");

            var phishCount = 0;
            var legitCount = 0;

            pattern = RegExp(this.onlyDomain, 'g');

            for (var i = 0; i < imgTags.length; i++) {
                var src = imgTags[i].getAttribute("src");
                if (!src) continue;
                if (pattern.test(src)) {
                    legitCount++;
                } else if (src.charAt(0) == '/' && src.charAt(1) != '/') {
                    legitCount++;
                } else {
                    phishCount++;
                }
            }
            var totalCount = phishCount + legitCount;
            var outRequest = (phishCount / totalCount) * 100;

            if (outRequest < 22) {
                this.result["Request URL"] = "-1";
            } else if (outRequest >= 22 && outRequest < 61) {
                this.result["Request URL"] = "0";
            } else {
                this.result["Request URL"] = "1";
            }

        }

        // URL of Anchor feature's function
        const f13 = () => {
            var aTags = document.getElementsByTagName("a");

            phishCount = 0;
            legitCount = 0;
            var allhrefs = "";

            for (var i = 0; i < aTags.length; i++) {
                var hrefs = aTags[i].getAttribute("href");
                if (!hrefs) continue;
                allhrefs += hrefs + "       ";
                if (pattern.test(hrefs)) {
                    legitCount++;
                } else if (hrefs.charAt(0) == '#' || (hrefs.charAt(0) == '/' && hrefs.charAt(1) != '/')) {
                    legitCount++;
                } else {
                    phishCount++;
                }
            }
            totalCount = phishCount + legitCount;
            outRequest = (phishCount / totalCount) * 100;

            if (outRequest < 31) {
                this.result["Anchor"] = "-1";
            } else if (outRequest >= 31 && outRequest <= 67) {
                this.result["Anchor"] = "0";
            } else {
                this.result["Anchor"] = "1";
            }

        }

        // Links in script and link feature's function
        const f14 = () => {
            var mTags = document.getElementsByTagName("meta");
            var sTags = document.getElementsByTagName("script");
            var lTags = document.getElementsByTagName("link");

            phishCount = 0;
            legitCount = 0;

            allhrefs = "sTags  ";

            for (var i = 0; i < sTags.length; i++) {
                var sTag = sTags[i].getAttribute("src");
                if (sTag != null) {
                    allhrefs += sTag + "      ";
                    if (pattern.test(sTag)) {
                        legitCount++;
                    } else if (sTag.charAt(0) == '/' && sTag.charAt(1) != '/') {
                        legitCount++;
                    } else {
                        phishCount++;
                    }
                }
            }

            allhrefs += "      lTags   ";
            for (var i = 0; i < lTags.length; i++) {
                var lTag = lTags[i].getAttribute("href");
                if (!lTag) continue;
                allhrefs += lTag + "       ";
                if (pattern.test(lTag)) {
                    legitCount++;
                } else if (lTag.charAt(0) == '/' && lTag.charAt(1) != '/') {
                    legitCount++;
                } else {
                    phishCount++;
                }
            }

            totalCount = phishCount + legitCount;
            outRequest = (phishCount / totalCount) * 100;

            if (outRequest < 17) {
                this.result["Script & Link"] = "-1";
            } else if (outRequest >= 17 && outRequest <= 81) {
                this.result["Script & Link"] = "0";
            } else {
                this.result["Script & Link"] = "1";
            }
        }

        // Server Form Handler feature's function
        const f15 = () => {
            var forms = document.getElementsByTagName("form");
            var res = "-1";

            for (var i = 0; i < forms.length; i++) {
                var action = forms[i].getAttribute("action");
                if (!action || action == "") {
                    res = "1";
                    break;
                } else if (!(action.charAt(0) == "/" || pattern.test(action))) {
                    res = "0";
                }
            }
            this.result["SFH"] = res;

        }

        // Submitting to mail feature's function
        const f16 = () => {
            var forms = document.getElementsByTagName("form");
            var res = "-1";

            for (var i = 0; i < forms.length; i++) {
                var action = forms[i].getAttribute("action");
                if (!action) continue;
                if (action.startsWith("mailto")) {
                    res = "1";
                    break;
                }
            }

            this.result["mailto"] = res;
        }

        // Using iFrame feature's function
        const f17 = () => {
            var iframes = document.getElementsByTagName("iframe");

            if (iframes.length == 0) {
                this.result["iFrames"] = "-1";
            } else {
                this.result["iFrames"] = "1";
            }
        }

        // Counting number of links
        const f18 = () => {
            var links = document.getElementsByTagName("a")

            if (links.length > 100) {
                this.result["numberOfLinks"] = "1";
            } else {
                this.result["numberOfLinks"] = "-1";
            }
        }

        // Detect right click event
        const f19 = () => {
            if (/(e|event|ev).(button|which)( +|)==( +|)(2|3)/.test(document.getElementsByTagName('html')[0].innerHTML)) {
                this.result["rightClickEvent"] = "1";
            } else {
                this.result["rightClickEvent"] = "-1";
            }
        }

        // Uses popup
        const f20 = () => {
            if (/alert\(/.test(document.getElementsByTagName('html')[0].innerHTML)) {
                this.result["usesAlert"] = "1";
            } else {
                this.result["usesAlert"] = "-1";
            }
        }

        // Uses shortening services
        const f21 = () => {
            if (/bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net/.test(document.getElementsByTagName('html')[0].innerHTML)) {
                this.result["usesShorteningService"] = "1";
            } else {
                this.result["usesShorteningService"] = "-1";
            }
        }

        // Running all feature functions.
        f1();
        f2();
        f3();
        f4();
        f5();
        f6();
        f7();
        f8();
        f9();
        f10();
        f11();
        f12();
        f13();
        f14();
        f15();
        f16();
        f17();
        f18();
        f19();
        f20();
        f21();

        // Sending results to background script.
        chrome.runtime.sendMessage(this.result);

        // Listening warning notification from the background script.
        chrome.runtime.onMessage.addListener(
            function (request, sender, sendResponse) {
                if (request.action == "notify") {
                    alert("Warning! This might be an unsafe website to Browse. Do You Still Want To Continue?");
                }
            }
        );
    }
}.init();
