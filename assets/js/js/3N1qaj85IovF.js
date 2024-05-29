(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
'use strict';

/**
 * algorithm specification
 */
var keyType = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: { name: 'SHA-256' }
};

var agentAuthUrlParts = {
    registrationUrl: '/device/cookies',
    verificationUrl: '/device/cookies/validate',
    beacon: '/beacon',
}

var cryptoTag = 'crypto-not-supported';

var localStorageKeys = {
    prvKey:'VM_AGENTAUTH_PRV_KEY',
    publicKey: 'VM_AGENTAUTH_PUB_KEY',
    accessToken: 'VM_AGENTAUTH_TOKEN'
}

var sessionKey = {
        /**
         * Browser do not support crypto flow
         */
        NotSupported : 0,
        /**
         * User is eligible for agentAuth and registered.
         */
        Registered : 1,
        /**
         * User is not eligible for agentAuth
         */
        NotEligible : 2
}

var daysBeforeTokenRefresh = 7;

/**
 * convert str to uint8 format
 * @param str - String to be encoded
 * @return Array
 */
function strToUint8(str) {
    return new TextEncoder().encode(str);
}

/**
 * convert string to base64 format
 * @param str - String to be converted to base64
 * @return String
 */
function strToUrlBase64(str) {
    return binaryToUrlBase64(utf8ToBinaryString(str));
}

/**
 * convert binary to base64 format
 * @param bin - String to be converted to base64
 * @return String
 */
function binaryToUrlBase64(bin) {
    return btoa(bin)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+/g, '');
}

/**
 * convert utf8 to binary string format
 * @param str - String to be converted to binary string
 * @return String
 */
function utf8ToBinaryString(str) {
    var escstr = encodeURIComponent(str);
    var binstr = escstr.replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode(parseInt(p1, 16));
    });

    return binstr;
}

/**
 * convert uint8 to base64 format
 * @param uint8 - Array buffer to be converted to base64
 * @return String
 */
function uint8ToUrlBase64(uint8) {
    var binary = '';
    uint8.forEach(function (code) {
        binary += String.fromCharCode(code);
    });
    return binaryToUrlBase64(binary);
}

/**
 * create signature and jwt from payload and header
 * @param publicKey - String
 * @param prvKey - String
 * @param payload - Object
 * @return String
 */
function signAndGenerateJWT(publicKey, prvKey, payload) {
    var headers = {
        typ: 'dpop+jwt',
        alg: 'ES256',
        jwk: publicKey
    };
    var jws = {
        headers: strToUrlBase64(JSON.stringify(headers)),
        payload: strToUrlBase64(JSON.stringify(payload))
    };
    var privileges = ['sign'];
    return window.crypto.subtle
        .importKey('jwk', prvKey, keyType, true, privileges)
        .then(function (prvKey) {
            var data = strToUint8(jws.headers + '.' + jws.payload);
            var sigType = { name: keyType.name, hash: keyType.hash };

            return window.crypto.subtle.sign(sigType, prvKey, data).then(function (signature) {
                jws.signature = uint8ToUrlBase64(new Uint8Array(signature));
                return jws.headers + '.' + jws.payload + '.' + jws.signature;
            });
        });
}

/**
 * generate crypto key pair via subtle crypto
 * @return Promise
 */
function generateKey() {
    var privileges = ['sign', 'verify'];
    return window.crypto.subtle.generateKey(keyType, true, privileges).then(function (key) {
        return window.crypto.subtle.exportKey('jwk', key.privateKey);
    });
}

/**
 * generate public key
 * @param jwk - Object
 * @return Object
 */
function generatePublicKey(jwk) {
    var cloneKey = Object.assign({}, jwk);
    delete cloneKey.d;
    cloneKey.key_ops = ['verify'];
    return cloneKey;
}


/**
 * get Item from Local storage
 * @param key - string
 * @return Object
 */
function getItemFromLS(key) {
    var valueString = localStorage.getItem(key);
    return valueString ? valueString : '';
}


/**
 * store value in localstorage
 * @param key - string
 * @param value - string
 * @return Object
 */
function setItemInLS(key, value) {
    return localStorage.setItem(key, value);
}


/**
 * get Item from Local storage
 * @param key - string
 * @return Object
 */
function getCrytoKeyFromLS(key) {
    var valueString = getItemFromLS(key);
    return valueString ? JSON.parse(valueString) : null;
}

/**
 * store value in localstorage
 * @param key - string
 * @param value - crypto key
 * @return Object
 */
function setCryptoKeyInLS(key, value) {
    var valueString = JSON.stringify(value);
    return setItemInLS(key, valueString);
}

/**
 * dispatch agent auth event to update parent from iframe with session detail
 * @param data - Object
 */
function dispatchAgentAuthRegistrationEvent (sessionKey){
    var data = {sessionKey: sessionKey};
    var event = new CustomEvent("agentAuthRegistrationSuccess", {detail: data});
    window.dispatchEvent(event);
}

/**
 * store access token in local storage and update parent from iframe
 * @param data - Object
 */
function processCookieApiResponse(data) {
    var accessToken = JSON.parse(data.response).access_token;
    setItemInLS(localStorageKeys.accessToken, accessToken);
    dispatchAgentAuthRegistrationEvent(sessionKey.Registered);
}


/**
 * check string value for true
 * @param key - string
 * @param value - crypto key
 * @return Object
 */
function checkStringToBoolean(value) {
    return value === 'true';
}

/**
 * fetch access token abd cookie with agentid from cookie issuance api
 * @param jwt - String
 */
function getAccessToken(jwt, accessToken) {
    var xhr = new XMLHttpRequest();
    var params = JSON.stringify({
        "src": "js",
        "srcv": "1.2.1"
    });

    xhr.open('POST', agentAuthUrlParts.registrationUrl, true);
    xhr.withCredentials = true;
    xhr.setRequestHeader('DPoP', jwt);
    xhr.setRequestHeader('Authorization', accessToken);
    xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
    xhr.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200)
            processCookieApiResponse(this);
    };
    xhr.send(params);
}

/**
 * redirect to identity with amr token
 * @param data - Object
 */
function redirectToIdentity(data) {
    var parsedData = data && data.response ? JSON.parse(data.response): {};
    var event = new CustomEvent("agentAuthVerificationComplete", {detail: data && data.status == 200 ? parsedData.device_id_token : ''});
    window.dispatchEvent(event);
}

/**
 * fetch identity token and validate cookie for agent id
 * @param data - Object
 */
function getAccessTokenVerify(jwt, accessToken, nonce) {
    var xhr = new XMLHttpRequest();
    var params = JSON.stringify({
        "nonce": nonce,
        "src": "js",
        "srcv": "1.2.1"
    });

    xhr.open('POST', agentAuthUrlParts.verificationUrl, true);
    xhr.withCredentials = true;
    xhr.setRequestHeader('DPoP', jwt);
    xhr.setRequestHeader('Authorization','DPoP' +" "+ accessToken);
    xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
    xhr.onreadystatechange = function () {
        if (this.readyState == 4)
            redirectToIdentity(this);
    };
    xhr.send(params);
}

/**
 * event listener for authRegistration event to initiate flow
 * @param urlparts - String
 * @param method - String
 * @return Object
 */
function createPayload(urlparts, method) {
    return {
        "jti": Math.random().toString(16).slice(2,9),
        "htm": method,
        "htu": location.protocol + '//' + location.host + urlparts,
        "iat": Math.round(Date.now()/1000)
    };
}

/**
 * check for ie and update crypto
 */
 function addCryptoIESupport() {
    if((/Edge/.test(navigator.userAgent))||document.documentMode) {
        window.crypto = window.msCrypto;
    };
}

/**
 * log user agent detail using beacon api
 * @param userAgent - string
 */
function logAgentAuthEvents(tag, step, userType) {
    var params = '?tag='+ tag + '&step='+ step + '&userType=' + userType;
    var xhr = new XMLHttpRequest();
    var url = agentAuthUrlParts.beacon + params;
    xhr.open("GET", url, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(null);
}

/**
 * check for crypto support
 */
function isCryptoSupported() {
    if(window.crypto && window.crypto.subtle && window.crypto.subtle.sign && window.crypto.subtle.generateKey && window.crypto.subtle.exportKey) {
        return true;
    }
    return false;
}

/**
 * check for access token refresh
 */
function isTokenRefresh(accessToken) {
    if (accessToken) {
        var encodedPayload = accessToken.split('.')[1];
        var decodePayload = JSON.parse(atob(encodedPayload));
        var todayDateInSeconds = Math.round(Date.now() / 1000);

        return (
            decodePayload.exp <
            todayDateInSeconds + (daysBeforeTokenRefresh * 3600 * 24)
        );
    } else {
        return false;
    }
}

/**
 * Initiate agent Authentication registration flow
 */
function initiateRegistrationFlow() {
    return generateKey().then(function (jwk) {
        var payload = createPayload(agentAuthUrlParts.registrationUrl, 'POST');
        var publicKey = generatePublicKey(jwk);

        setCryptoKeyInLS(localStorageKeys.publicKey, publicKey);
        setCryptoKeyInLS(localStorageKeys.prvKey, jwk);
        return signAndGenerateJWT(publicKey, jwk, payload).then(function (jwt) {
            getAccessToken(jwt, '');
        });
    });
}

/**
 * Initiate agent Authentication registration flow
 */
function initiateTokenRefreshFlow() {
    var accessToken = getItemFromLS(localStorageKeys.accessToken);
    if(accessToken && isTokenRefresh(accessToken)) {
        var payload = createPayload(agentAuthUrlParts.registrationUrl, 'POST');
        var publicKeyLocalStorage = getCrytoKeyFromLS(localStorageKeys.publicKey);
        var prvKeyLocalStorage = getCrytoKeyFromLS(localStorageKeys.prvKey);
        return signAndGenerateJWT(publicKeyLocalStorage, prvKeyLocalStorage, payload).then(function (jwt) {
            getAccessToken(jwt, accessToken);
        });
    } else {
        dispatchAgentAuthRegistrationEvent();
        return ;
    }
}

/**
 * Initiate agent Authentication verification flow
 */
function initiateVerificationFlow(nonce) {
    var payload = createPayload(agentAuthUrlParts.verificationUrl, 'POST');
    var publicKeyLocalStorage = getCrytoKeyFromLS(localStorageKeys.publicKey);
    var prvKeyLocalStorage = getCrytoKeyFromLS(localStorageKeys.prvKey);
    var accessToken = getItemFromLS(localStorageKeys.accessToken)
    return signAndGenerateJWT(publicKeyLocalStorage, prvKeyLocalStorage, payload).then(function (jwt) {
        getAccessTokenVerify(jwt, accessToken, nonce);
    });
}


/**
 * event listener for authRegistration event to initiate flow
 */
window.addEventListener('agentAuthRegistration', function (e) {
    // check for ie and update crypto
    addCryptoIESupport();
    if(isCryptoSupported()){
        if(checkStringToBoolean(e.detail.isAgentIdCookie)) {
            return initiateTokenRefreshFlow();
        } else {
            return initiateRegistrationFlow();
        }
    } else {
        // log user agent details when crypto is not supported
        logAgentAuthEvents(cryptoTag, 'agentAuthRegistration',  window.navigator.userAgent);
        dispatchAgentAuthRegistrationEvent(sessionKey.NotSupported);
    }
});

/**
 * event listener for agentAuthVerification event to initiate flow
 */
window.addEventListener('agentAuthVerification', function (e) {
    // check for ie and update crypto
    addCryptoIESupport();
    if(isCryptoSupported()){
        if(checkStringToBoolean(e.detail.isAgentIdCookie)) {
            return initiateVerificationFlow(e.detail.nonce);
        } else {
            redirectToIdentity(null);
        }
    } else {
        // log user agent details when crypto is not supported
        logAgentAuthEvents(cryptoTag, 'agentAuthVerification', window.navigator.userAgent);
        redirectToIdentity(null);
    }
});

},{}],2:[function(require,module,exports){
'use strict';

/**
 * Checks if the element contains the specified class name.
 */
function containsClass(element, className) {
    if (!element || typeof className !== 'string') {
        return false;
    }
    return element.className.trim().split(/\s+/gi).indexOf(className) > -1 ;
}

function updateQueryStringParameter(uri, key, value) {
    var re = new RegExp('([?&])' + key + '=.*?(&|$)', 'i');
    var separator = uri.indexOf('?') !== -1 ? '&' : '?';
    if (uri.match(re)) {
        return uri.replace(re, '$1' + key + '=' + value + '$2');
    }
    else {
        return uri + separator + key + '=' + value;
    }
}

function onLanguageChange(event) {
    var newLang = event.target.value;
    window.location.href = updateQueryStringParameter(window.location.href, 'lang', newLang);
}

function disableFormButtons() {
    var agreeButton = document.querySelector('.agree'),
        disagreeButton = document.querySelector('.disagree');

    if (agreeButton) {
        agreeButton.disabled = true;
    }
    if (disagreeButton) {
        disagreeButton.disabled = true;
    }

}

function handleDoubleSubmit(event) {
    var formElement = event.currentTarget,
        altSubmitField = formElement.querySelectorAll('input[data-name="alt-submit"]')[0];

    /* This creates another submit input in the DOM and sets it's name and value
        to the button that was clicked
     */
    if (!altSubmitField) {
        altSubmitField = document.createElement('input');
        altSubmitField.setAttribute('type', 'hidden');
        altSubmitField.setAttribute('data-name', 'alt-submit');
        formElement.appendChild(altSubmitField);
    }

    if ((event.type === 'click' || event.type === 'touchstart') && event.target.type === 'submit') {
        altSubmitField.setAttribute('name', event.target.name);
        altSubmitField.setAttribute('value', event.target.value);
    }

    if (event.type === 'submit') {
        disableFormButtons();
    }

    return true;
}

function addClass(element, name) {
    if (!containsClass(element, name)) {
        if ('classList' in element) {
            element.classList.add(name);
        } else {
            var c = element.className;
            element.className = c ? [c, name].join(' ') : name;
        }
    }
}

function removeClass(element, name) {
    if (containsClass(element, name)) {
        if ('classList' in element) {
            element.classList.remove(name);
        } else {
            var c = element.className;
            element.className = c.replace(new RegExp('(?:^|\\s+)' + name + '(?:\\s+|$)', 'g'), '');
        }
    }
}

function setupEUMoreOptionsToggle(tapEventName) {
    var toggleButtons = document.querySelectorAll('.boxed-content input[type="checkbox"]');
    var isTouchStart = tapEventName === 'touchstart';

    if(!toggleButtons) {
        return;
    }

    Array.prototype.forEach.call(toggleButtons, function(toggleButton) {

        var toolTipElement = toggleButton.parentElement;
        var errorElement = toolTipElement.nextElementSibling;
        var changeCount = 0;

        if (isTouchStart) {
            document.body.addEventListener('touchstart', function() {
                removeClass(toolTipElement, 'touched-once');
            });
        }
        toggleButton.addEventListener('change', function() {
            var tooltipText = '';

            if (isTouchStart && changeCount < 1) {
                this.checked = true;
                addClass(toolTipElement, 'checked-active');
                removeClass(errorElement, 'active');
                changeCount++;
                addClass(toolTipElement, 'touched-once');
                return;
            }

            removeClass(toolTipElement, 'touched-once');
            if (toggleButton.checked) {
                changeCount = 0;
                tooltipText = toolTipElement.getAttribute('data-tooltip-on');
                addClass(toolTipElement, 'checked-active');
                removeClass(errorElement, 'active');
            } else {
                tooltipText = toolTipElement.getAttribute('data-tooltip-off');
                removeClass(toolTipElement, 'checked-active');
                addClass(errorElement, 'active');
            }
            if (tooltipText) {
                toolTipElement.setAttribute('data-tooltip', tooltipText);
            }
        });
    });
}

function displayScrollToContinue(tapEvent) {

    var footer = document.querySelector('.footer');
    var scrollContainer = document.querySelector('.scroll-container');
    var readMoreTip = document.querySelector('.read-more-tip');
    var bodyElement = document.querySelector('body');
    var parkPage = document.querySelector('.park-page-body');
    var tppPage = document.querySelector('.tpp');
    var EUBtnGroup = document.querySelector('.eu .btn-group');
    var singlePage = document.querySelector('.eu-single-page');
    var manageOptionsPage = document.querySelector('.manage-options');

    if (parkPage) {
        return;
    }

    if (tppPage && EUBtnGroup) {
        addClass(EUBtnGroup, 'active');
        return;
    }

    var isBodyScrolling;

    var scrollBox;
    if (bodyElement.clientHeight > window.innerHeight + 100 && !(window.innerHeight + window.pageYOffset + 50 > document.body.scrollHeight)) {
        isBodyScrolling = true;
        scrollBox = bodyElement;
    }

    if (scrollBox) {
        if(scrollContainer && footer) {

            if (manageOptionsPage) {
                addClass(manageOptionsPage, 'active');
            } else if(!singlePage) {
                addClass(footer, 'active');
                addClass(scrollContainer, 'active');
            }

            readMoreTip.addEventListener(tapEvent, function() {
                isBodyScrolling ? window.scrollBy(0, window.innerHeight) : scrollBox.scrollTop += scrollBox.clientHeight;
                if (isBodyScrolling) {
                    if (window.innerHeight + window.pageYOffset + 50 > document.body.scrollHeight) {
                        removeClass(scrollContainer, 'active');
                        removeClass(footer, 'active');
                    }
                } else {
                    if (scrollBox.offsetHeight + scrollBox.scrollTop + 50 >= scrollBox.scrollHeight) {
                        removeClass(scrollContainer, 'active');
                        removeClass(footer, 'active');
                    }
                }
            });
        }
        if (EUBtnGroup) {
            EUBtnGroup.style.display = 'block';
        }
    } else if (EUBtnGroup && !singlePage) {
        if ((window.innerHeight - 50 > bodyElement.clientHeight)) {
            var paddingValue = (window.innerHeight - bodyElement.clientHeight - 50);
            paddingValue = paddingValue > 0 ? paddingValue : 0;
            if (window.innerWidth > 1000) {
                paddingValue = 0;
            }
            addClass(EUBtnGroup, 'active');
            EUBtnGroup.style.paddingTop = paddingValue + 'px';
        } else {
            EUBtnGroup.style.display = 'block';
        }
    }

}

function showCookieFail() {
    var cookieAlert = document.getElementById('cookieWarning');
    addClass(cookieAlert, 'active');
}

function checkCookie(){
    var cookieEnabled = navigator.cookieEnabled;
    if (!cookieEnabled){
        document.cookie = 'testcookie';
        cookieEnabled = document.cookie.indexOf('testcookie')!= -1;
    }
    return cookieEnabled || showCookieFail();
}

function detectIE(scrollContainer, footer) {

    var IEInterval;

    var IEScrollHandler = function() {
        if (scrollContainer && footer) {
            if (window.innerHeight + window.pageYOffset + 50 > document.body.scrollHeight) {
                removeClass(scrollContainer, 'active');
                removeClass(footer, 'active');
                window.clearInterval(IEInterval);
            }
        }
    };

    if (/Edge/.test(navigator.userAgent)) {
        addClass(document.body, 'edge');
    }

    if (document.documentMode) {
        addClass(document.body, 'ie');
        IEInterval = window.setInterval(IEScrollHandler, 200);
    }
}

function fireBeacon(element, tag) {
    var xhr = new XMLHttpRequest();
    var url = '/beacon';
    var consentForm = document.querySelector('.consent-form');
    var sessionId;
    var isSDK;
    var tos;
    var userType;
    var brandBid;
    var step;
    var country;

    if (consentForm) {
        sessionId = document.querySelector('[name="sessionId"]');
        isSDK = document.querySelector('[name="isSDK"]');
        tos = document.querySelector('[name="tosId"]');
        brandBid = document.querySelector('[name="brandBid"]');
        userType = document.querySelector('[name="userType"]');
        step = document.querySelector('[name="consentCollectionStep"]');
        country = document.querySelector('[name="country"]');
    }

    url = url + '?sessionId=' + (sessionId ? sessionId.value : '');
    url = url + '&sdk=' + (isSDK ? isSDK.value : '');
    url = url + '&tag=' + tag;
    url = url + '&tos=' + (tos ? tos.value : '');
    url = url + '&brandBid=' + (brandBid ? brandBid.value : '');
    url = url + '&userType=' + (userType ? userType.value : '');
    url = url + '&step=' + (step ? step.value : '');
    url = url + '&country=' + (country ? country.value : '');

    if (consentForm) {
        xhr.open('GET', url, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(null);
    }

}

function setupBeacon() {
    var mailMoreOptionsToggle = document.getElementById('mail-checkbox');
    var purposeListToggle = document.querySelectorAll('input[id^="purpose-"]');
    var vendorListToggle = document.querySelectorAll('input[id^="vendor-"]');
    if (mailMoreOptionsToggle) {
        mailMoreOptionsToggle.addEventListener('change', function() {
            fireBeacon(mailMoreOptionsToggle, 'mail');
        });
    }
    if (purposeListToggle) {
        Array.prototype.forEach.call(purposeListToggle, function(purpose) {
            purpose.addEventListener('change', function() {
                fireBeacon(purpose, purpose.id);
            });
        });
    }
    if (vendorListToggle) {
        Array.prototype.forEach.call(vendorListToggle, function(vendor) {
            vendor.addEventListener('change', function() {
                fireBeacon(vendor, vendor.id);
            });
        });
    }
}

function setupSinglePageExpand(tapEvent) {
    var expandLearnMoreLink = document.querySelector('.expand-learn-more-link');
    var agreeBtnGroup = document.querySelector('.eu .eu-single-page .agree-button-group');
    var manageOptionsBtnGroup = document.querySelector('.eu .eu-single-page .more-options-button-group');
    var singlePageDataSection = document.getElementById('single-page-data');
    var singlePagePartnersSection = document.getElementById('single-page-partners');
    var singlePageMailSection = document.getElementById('single-page-mail');
    var consentStepBody = document.querySelector('.consent-step-body.scrollbox');

    if (expandLearnMoreLink) {
        addClass(expandLearnMoreLink, 'active');
        expandLearnMoreLink.addEventListener(tapEvent, function() {

            if (!containsClass(agreeBtnGroup, 'active')) {
                fireBeacon(expandLearnMoreLink, 'singlePageExpanded');
            }

            removeClass(expandLearnMoreLink, 'active');

            if (agreeBtnGroup) {
                addClass(agreeBtnGroup, 'active');
            }

            if (manageOptionsBtnGroup) {
                addClass(manageOptionsBtnGroup, 'active');
            }

            if (singlePageDataSection) {
                addClass(singlePageDataSection, 'active');
            }

            if (singlePagePartnersSection) {
                addClass(singlePagePartnersSection, 'active');
            }

            if (singlePageMailSection) {
                addClass(singlePageMailSection, 'active');
            }

            if (consentStepBody) {
                addClass(consentStepBody, 'expanded');
            }
        });
    }
}

function setupExperimentalPage(tapEvent) {
    var expandLearnMoreLink = document.querySelector('.experimental-expand-learn-more');
    var learnMoreSection = document.querySelector('.experimental-learn-more');
    if (expandLearnMoreLink && learnMoreSection) {
        expandLearnMoreLink.addEventListener(tapEvent, function() {
            addClass(expandLearnMoreLink, 'plain-text');
            removeClass(learnMoreSection, 'hidden');
        });
    }
}
function setupFakeBgPage(tapEvent) {
    var expandLearnMoreLink = document.querySelector('.expand-learn-more');
    var learnMoreSection = document.querySelector('.learn-more-content');
    if (expandLearnMoreLink && learnMoreSection) {
        expandLearnMoreLink.addEventListener(tapEvent, function() {
            addClass(expandLearnMoreLink, 'plain-text');
            removeClass(learnMoreSection, 'hidden');
        });
    }
}

/* consent 1.8 */
function setupOptinAll(tapEvent) {
    var contianerElm = document.querySelector('#consent-page .enable-optin-all');
    var ctaSelectAll;
    var selectElments;
    var ctaSelectAllToggle;
    if (contianerElm) {
        ctaSelectAll = contianerElm.querySelector('.optin-all');
        ctaSelectAllToggle = ctaSelectAll.querySelector('.toggle-control');
        selectElments = contianerElm.querySelectorAll('.optin');
        if (ctaSelectAll && selectElments) {
            contianerElm.querySelector('.optin-all').style.display = 'inline-block';
            ctaSelectAll.addEventListener(tapEvent, function() {
                var newState = !ctaSelectAllToggle.checked;
                for (var i = 0; i < selectElments.length; i++) {
                    selectElments[i].checked = newState;
                }
                ctaSelectAllToggle.checked = newState;
            });
        }
    }
}

/* consent 2.0 */
function selectAllConsentAndLegitAll(tapEvent) {
    setIABToggleAllBtnState();
    var legitimateInterestToggles,
        consentToggles;
    var purposeConsentAllElm = document.querySelector('#consent-page #select-consent-all-purpose');
    var purposeLegitAllElm = document.querySelector('#consent-page #select-legit-all-purpose');
    var partnerConsentAllElm = document.querySelector('#consent-page #select-consent-all-partner');
    var partnerLegitAllElm = document.querySelector('#consent-page #select-legit-all-partner');
    var IABData = document.querySelector('#consent-page .iab-data');
    var consentPageElement = document.getElementById('consent-page');

    if (IABData) {
        legitimateInterestToggles = IABData.querySelectorAll('.legit .optin');
        consentToggles = IABData.querySelectorAll('.consent .optin');
    }

    if (purposeLegitAllElm && partnerLegitAllElm && legitimateInterestToggles.length > 0) {
        var purposeLegitAllInputElm = purposeLegitAllElm.querySelector('input[type="checkbox"]');
        var partnerLegitAllInputElm = partnerLegitAllElm.querySelector('input[type="checkbox"]');

        purposeLegitAllElm.addEventListener(tapEvent, function(event) {
            event.preventDefault();

            var purposeLegitToggleState = !purposeLegitAllInputElm.checked;

            partnerLegitAllInputElm.checked = purposeLegitToggleState;
            for (var i = 0; i < legitimateInterestToggles.length; i++) {
                legitimateInterestToggles[i].checked = purposeLegitToggleState;
            }
            purposeLegitAllInputElm.checked = purposeLegitToggleState;
        });

        partnerLegitAllElm.addEventListener(tapEvent, function(event) {
            event.preventDefault();
            var partnerLegitToggleState = !partnerLegitAllInputElm.checked;

            purposeLegitAllInputElm.checked = partnerLegitToggleState;
            for (var i = 0; i < legitimateInterestToggles.length; i++) {
                legitimateInterestToggles[i].checked = partnerLegitToggleState;
            }
            partnerLegitAllInputElm.checked = partnerLegitToggleState;
        });
    }

   if (purposeConsentAllElm && partnerConsentAllElm && consentToggles.length > 0) {
        var purposeConsentAllInputElm = purposeConsentAllElm.querySelector('input[type="checkbox"]');
        var partnerConsentAllInputElm = partnerConsentAllElm.querySelector('input[type="checkbox"]');

        purposeConsentAllElm.addEventListener(tapEvent, function(event) {
            event.preventDefault();
            var purposeConsentToggleState = !purposeConsentAllInputElm.checked;
            if (consentPageElement.getAttribute("class").includes("variant-1")) {
                purposeConsentAllElm.classList.toggle('primary');
            }

            partnerConsentAllInputElm.checked = purposeConsentToggleState;
            for (var i = 0; i < consentToggles.length; i++) {
                consentToggles[i].checked = purposeConsentToggleState;
            }
            purposeConsentAllInputElm.checked = purposeConsentToggleState
        });

        partnerConsentAllElm.addEventListener(tapEvent, function(event) {
            event.preventDefault();
            var partnerConsentToggleState = !partnerConsentAllInputElm.checked;
            if (consentPageElement.getAttribute("class").includes("variant-1")) {
                purposeConsentAllElm.classList.toggle('primary');
            }

            purposeConsentAllInputElm.checked = partnerConsentToggleState;
            for (var i = 0; i < consentToggles.length; i++) {
                consentToggles[i].checked = partnerConsentToggleState;
            }
            partnerConsentAllInputElm.checked = partnerConsentToggleState
        });
    }
}

function setToggleAllBtnState(container, toggleType){
    var toggleAllButtonState = false;
    var allToggles = container.querySelectorAll('.switch.' + toggleType + ' input[type="checkbox"].optin').length;
    var allTogglesChecked = container.querySelectorAll('.switch.' + toggleType + ' input[type="checkbox"]:checked.optin').length;
    if (allToggles > 0 && allTogglesChecked === allToggles) {
        toggleAllButtonState = true;
    }

    var selectAllBtn = container.querySelector('#select-' + toggleType + '-all-purpose input[type="checkbox"].optin');
    if (selectAllBtn) {
        selectAllBtn.checked = toggleAllButtonState;
    }
}

function setIABToggleAllBtnState() {
    var iabDataContainer = document.querySelector('#iab-partners .iab-data');
    if (iabDataContainer) {
        setToggleAllBtnState(iabDataContainer, "legit");
        setToggleAllBtnState(iabDataContainer, "consent");
    }
}

function selectAllFirstPartyDataAll(tapEvent) {
    var consentAllElm = document.querySelector('#consent-page #first-party-toggle-all');
    var consentToggles = document.querySelectorAll('#consent-page .first-party .table-list .consent .optin');
    var consentPageElement = document.getElementById('consent-page');

    if (consentAllElm && consentToggles.length > 0) {
        var consentAllInputElm = consentAllElm.querySelector('input[type="checkbox"]');
        consentAllElm.addEventListener(tapEvent, function(event) {
            event.preventDefault();
            var consentAllElmToggleState = !consentAllInputElm.checked;
            if (consentPageElement.getAttribute("class").includes("variant-1")) {
                consentAllElm.classList.toggle('primary');
            }

            for (var i = 0; i < consentToggles.length; i++) {
                consentToggles[i].checked = consentAllElmToggleState
            }
            consentAllInputElm.checked = consentAllElmToggleState;
        });
    }
}

function selectAllSocialPartners(tapEvent) {
    var consentAllElm = document.querySelector('#consent-page #pce-toggle-all');
    var consentToggles = document.querySelectorAll('#consent-page .third-party .pce .consent .optin');

    if (consentAllElm && consentToggles.length > 0) {
        var consentAllInputElm = consentAllElm.querySelector('input[type="checkbox"]');
        if(consentAllInputElm){
            consentAllElm.addEventListener(tapEvent, function(event) {
                event.preventDefault();
                var consentAllElmToggleState = !consentAllInputElm.checked;
                for (var i = 0; i < consentToggles.length; i++) {
                    consentToggles[i].checked = consentAllElmToggleState
                }
               consentAllInputElm.checked = consentAllElmToggleState;
            });
        }
    }
}

/**
 * toggleOnRelatedPartners
 * @param partnerListElements - partner Elements associated with the selected purpose
 * @param toggleType  -  legit or consent
 */

function toggleOnRelatedPartners(partnerListElements, toggleType) {
    for (var i = 0; i < partnerListElements.length; i++) {
        var partnerToggleElement = document.querySelector('#' + partnerListElements[i].dataset.partnerId + ' [data-toggle-type=' + toggleType + ']');
        if (partnerToggleElement) {
            partnerToggleElement.checked = true;
        }
    }
}

/**
 * toggleOffRelatedPartners
 * @param partnerListElements - partner Elements associated with the selected purpose
 * @param toggleType  - legit or consent
 */
function toggleOffRelatedPartners(partnerListElements, toggleType) {
    for (var i = 0; i < partnerListElements.length; i++) {
        var partnerElement = document.getElementById(partnerListElements[i].dataset.partnerId);
        var partnerToggleElement;
        if(partnerElement){
            partnerToggleElement = partnerElement.querySelector('[data-toggle-type=' + toggleType + '][type="checkbox"]:checked');
        }
        if (partnerToggleElement) {
            var purposeListElements = partnerElement.querySelectorAll('.more-details .details-list .values .value');
            var purposeSelected = false;
            for (var j = 0; j < purposeListElements.length; j++) {
                var checkedElement = document.querySelector('#' + purposeListElements[j].dataset.purposeId + ' [data-toggle-type=' + toggleType + '][type="checkbox"]:checked');
                if (checkedElement) {
                    purposeSelected = true;
                    break;
                }
            }
            if (!purposeSelected) {
                partnerToggleElement.checked = false;
            }
        }
    }
}
/*
 * Toggle partners for consent 2.0 workflow
 *
 * 1. toggleOnPurpose legitimateInterest or Consent on Purpose Tab
 *    - All corresponding partners list for each purpose should be selected in partner tab
 *
 * 2. toggleOffPurpose legitimateInterest or Consent on Purpose Tab
 *    - Ensure all the purposes of the partners associated are turned off, only then toggle off
 *      partner list for the corresponding purpose
 *
 * @param tapEvent -- click event
 */
function togglePurposeAndPartners(tapEvent) {
    var IABData = document.querySelector('#consent-page .iab-data');
    if (!IABData) {
        return;
    }
    IABData.addEventListener(tapEvent, function(event) {
        if (!event.target.hasAttribute('data-toggle-type')) {
            return;
        }
        var toggleElement = event.target;
        if (!IABData.contains(toggleElement)) {
            return;
        }
        if (toggleElement.name.includes("data-iab-partner")) {
            return;
        }
        var toggleType = toggleElement.dataset.toggleType;
        var purposeElement = document.getElementById(toggleElement.dataset.purposeId);
        if (purposeElement) {
            var partnerListElements = purposeElement.querySelectorAll('.iab-partners .purpose-partners .list-item');
            if (toggleElement.checked) {
                toggleOnRelatedPartners(partnerListElements, toggleType);
            } else {
                toggleOffRelatedPartners(partnerListElements, toggleType);
            }
        }
    });
}

function setupTCFVendorDataFetch() {
    var iabPartnersContainer = document.querySelector('#tcf2-layer2 .tcfv2_2 .iab-partners-view .iab-partners');
    if (!iabPartnersContainer) {
        return;
    }
    var lang = document.querySelector('body').getAttribute('data-lang') || '';
    var sessionIdElm = document.querySelector('[name="sessionId"]');
    var sessionId = "";
    if (sessionIdElm) {
        sessionId = sessionIdElm.value;
    }
    if (!sessionId) {
        var sessionIdElm = document.querySelector('#consent-page');
        if (sessionIdElm) {
            sessionId = sessionIdElm.getAttribute('data-session') || '';
        }
    }
    var errorWidget = document.querySelector('#xhr-error-widget');
    var loaderWidget = document.querySelector('#xhr-loader-widget');

    var errorHtml = "";
    var loaderHtml = "";
    if (errorWidget) {
        var errorHtml = errorWidget.innerHTML;
    }
    if (loaderWidget) {
        var loaderHtml = loaderWidget.innerHTML;
    }

    var vendorDataCallStatus = {};

    function getDeviceStorageDisclosureDataHtml(vendorOid) {
        if (vendorDataCallStatus[vendorOid]) {
            return; // data already fetched.
        }
        var dataContainer = iabPartnersContainer.querySelector('.iab-partner #partner-'+ vendorOid +' .toggle-pane .device-storage-container');
        if (!dataContainer) {
            return; // container to insert the html is missing
        }
        dataContainer.innerHTML = loaderHtml;
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
            if (this.readyState == 4) {
                if (this.status == 200) {
                    var dataHtml = this.responseText;
                    dataContainer.innerHTML = dataHtml;
                    vendorDataCallStatus[vendorOid] = true; // setting the flag for the vendor to avoid fetching again
                } else  {
                    dataContainer.innerHTML = errorHtml;
                    vendorDataCallStatus[vendorOid] = false;
                }
            }
        };
        var xhrBasePath = '?vendorOid=' + vendorOid + '&lang=' + lang;
        var xhrEndPoint = '';
        if (sessionId) {
            //xhrEndPoint = '/v2/vendor-data' + xhrBasePath + '&sessionId='+sessionId;
            xhrEndPoint = '/v2/tcfV3-vendor-data' + xhrBasePath;
        } else {
            xhrEndPoint = '/v2/tcfV3-vendor-data' + xhrBasePath;
        }
        xhttp.open('GET', xhrEndPoint, true);
        xhttp.send();
        vendorDataCallStatus[vendorOid] = "progress"; // setting the flag for the vendor to avoid duplicate calls

    }
    iabPartnersContainer.querySelectorAll('.iab-partner input[type="checkbox"][name="toggle-cookie-max-age"]').forEach(function (toggle) {
        toggle.addEventListener('change', function(e) {
            if (e.currentTarget.checked) {
                var vendorOid = e.currentTarget.getAttribute('data-oid');
                getDeviceStorageDisclosureDataHtml(vendorOid);
            }
        });
    })
    // setting up 'try again' action
    iabPartnersContainer.querySelectorAll('.iab-partner .device-storage-container').forEach( function (elm){
        elm.addEventListener('click', function(e) {
            if (containsClass(e.target, 'xhr-retry-btn')){
                var vendorOid = e.currentTarget.getAttribute('data-oid');
                getDeviceStorageDisclosureDataHtml(vendorOid);
            }
        });

    });
}

function setupTppSelectAll(tapEvent) {
    var tppVendors = document.querySelector('.tpp.tpp-vendors');

    if (!tppVendors) {
        return;
    }

    var iabVendors = document.querySelectorAll('#iabVendors input[type="checkbox"]');
    var checkediabVendors = document.querySelectorAll('#iabVendors input[type="checkbox"]:checked');
    var otherVendors = document.querySelectorAll('#otherVendors input[type="checkbox"]');
    var checkedOtherVendors = document.querySelectorAll('#otherVendors input[type="checkbox"]:checked');
    var IABtppSelectAll = document.querySelector('#iabVendors .tpp-select-all');
    var IABtppDeslectAll = document.querySelector('#iabVendors .tpp-deselect-all');
    var otherstppSelectAll = document.querySelector('#otherVendors .tpp-select-all');
    var otherstppDeselectAll = document.querySelector('#otherVendors .tpp-deselect-all');

    function setRightLabel(selectAll, deselectAll, vendors, className) {
        checkediabVendors = document.querySelectorAll(className + ' input[type="checkbox"]:checked');
        if (checkediabVendors.length <= (vendors.length * 0.25)) {
            removeClass(deselectAll, 'active');
            addClass(selectAll, 'active');
        } else {
            removeClass(selectAll, 'active');
            addClass(deselectAll, 'active');
        }
    }

    if (IABtppSelectAll && IABtppDeslectAll && iabVendors) {

        setRightLabel(IABtppSelectAll, IABtppDeslectAll, iabVendors, '#iabVendors');

        IABtppSelectAll.addEventListener(tapEvent, function() {
            for (var i = 0; i < iabVendors.length; i++) {
                iabVendors[i].checked = true;
            }
            removeClass(IABtppSelectAll, 'active');
            addClass(IABtppDeslectAll, 'active');
        });

        IABtppDeslectAll.addEventListener(tapEvent, function () {
            for (var i = 0; i < iabVendors.length; i++) {
                iabVendors[i].checked = false;
            }
            removeClass(IABtppDeslectAll, 'active');
            addClass(IABtppSelectAll, 'active');
        });

        Array.prototype.forEach.call(iabVendors, function(vendor) {
            vendor.addEventListener('change', function() {
                setRightLabel(IABtppSelectAll, IABtppDeslectAll, iabVendors, '#iabVendors');
            });
        });
    }

    if (otherstppSelectAll && otherstppDeselectAll && otherVendors) {

        setRightLabel(otherstppSelectAll, otherstppDeselectAll, otherVendors, '#otherVendors');

        otherstppSelectAll.addEventListener(tapEvent, function() {
            for (var i = 0; i < otherVendors.length; i++) {
                otherVendors[i].checked = true;
            }
            removeClass(otherstppSelectAll, 'active');
            addClass(otherstppDeselectAll, 'active');
        });

        otherstppDeselectAll.addEventListener(tapEvent, function () {
            for (var i = 0; i < otherVendors.length; i++) {
                otherVendors[i].checked = false;
            }
            removeClass(otherstppDeselectAll, 'active');
            addClass(otherstppSelectAll, 'active');
        });

        Array.prototype.forEach.call(checkedOtherVendors, function(vendor) {
            vendor.addEventListener('change', function() {
                checkedOtherVendors = document.querySelectorAll('#otherVendors input[type="checkbox"]:checked');
                setRightLabel(otherstppSelectAll, otherstppDeselectAll, otherVendors, '#otherVendors');
            });
        });
    }
}

function manageLayerOneCTAState() {
    var wizardContentBody = document.querySelector('.con-wizard .wizard-body'),
        wizardFooter = document.querySelector('.con-wizard .wizard-footer'),
        btnPrimary = document.querySelector('.con-wizard .wizard-footer .btn.primary'),
        btnSecondary = document.querySelector('.con-wizard .wizard-footer .btn.secondary'),
        disableCssClass = 'disabled';
    if (!wizardContentBody || !btnPrimary) {
        return;
    }

    var checkScrollPosition = function () {
        var threshold = (wizardContentBody.scrollHeight - wizardContentBody.offsetHeight) - wizardContentBody.scrollTop;
        if (threshold < 20) {
            btnPrimary.disabled = false;
            btnPrimary.classList.remove(disableCssClass);
            btnSecondary.classList.remove(disableCssClass);
            wizardFooter.classList.add('scroll-bottom');
        } else {
            btnPrimary.disabled = true;
            btnPrimary.classList.add(disableCssClass);
            btnSecondary.classList.add(disableCssClass);
            wizardFooter.classList.remove('scroll-bottom');
        }
    }

    checkScrollPosition();
    wizardContentBody.addEventListener('scroll', checkScrollPosition);
}

/* Yahoo mail consent popup position*/
function setMailConsentServicesHoverPosition(tapEvent) {
    var serviceHoverElem = document.getElementById('info-hover-mail-services');
    var leftOffsetmargin = 5;
    var leftOffset = 0;
    var widthOffset = 0;
    var popupMaxWidthInPixel = 275;
    var handlerFunction = function() {
        leftOffset = serviceHoverElem.offsetLeft;
        if((leftOffset + widthOffset) > popupMaxWidthInPixel) {
            serviceHoverElem.style.setProperty('--services-hover-pos', '-'+ (popupMaxWidthInPixel-widthOffset)+'px');
        } else {
            serviceHoverElem.style.setProperty('--services-hover-pos', '-'+ (leftOffset-leftOffsetmargin)+'px');
        }
    };
    if (serviceHoverElem) {
        var leftOffset = serviceHoverElem.offsetLeft;
        var widthOffset = serviceHoverElem.offsetWidth;
        serviceHoverElem.addEventListener(tapEvent, handlerFunction);
        serviceHoverElem.addEventListener('hover', handlerFunction);
        handlerFunction();
    }
}

/* Yahoo mail consent popup Accept an decline ALL listner*/
function setMailConsentEventHandler(tapEvent) {
    var mailConsentElem = document.querySelector('.theme-2.mail-consent .mailbox-consent-type');
    var mailFeaturesOptin = document.getElementById('generalAnalysisConsent-consent-toggle-on');
    var mailFeaturesOptout = document.getElementById('generalAnalysisConsent-consent-toggle-off');
    var personalizedAdsOptin = document.getElementById('analysisOfCommunications-consent-toggle-on');
    var personalizedAdsOptout = document.getElementById('analysisOfCommunications-consent-toggle-off');
    var insightsCommOptin = document.getElementById('insightsFromCommunications-consent-toggle-on');
    var insightsCommOptout = document.getElementById('insightsFromCommunications-consent-toggle-off');
    var acceptAllHeaderElem = document.getElementById('mail-accept-all-1');
    var declineAllHeaderElem = document.getElementById('mail-decline-all-1');
    var acceptAllFooterElem = document.getElementById('mail-accept-all-2');
    var declineAllFooterElem = document.getElementById('mail-decline-all-2');
    var scrollContainerElem = document.getElementsByClassName('wizard-body')[0];
    var footerOptionElem = document.getElementById('mail-consent-option-footer');
    var doneBtnElm = document.querySelector('.mail-consent .btn.done-button');
    var doneBtnDisabledClassName = 'done-btn-disabled';
    var hiddenClassName = 'hidden';

    // controls are not populated dynamically. page is expected to have all 6 controls. also the done button is expected
    if (!mailFeaturesOptin || !mailFeaturesOptout || !personalizedAdsOptin || !personalizedAdsOptout || !insightsCommOptin || !insightsCommOptout || !doneBtnElm) {
        return false;
    }
    var scrollToBottom = function() {
        scrollContainerElem.scrollTo(0, scrollContainerElem.scrollHeight);
    };

    function hasAllConsentSelected() {
        return ((mailFeaturesOptin.checked || mailFeaturesOptout.checked) &&
            (personalizedAdsOptin.checked || personalizedAdsOptout.checked) &&
            (insightsCommOptin.checked || insightsCommOptout.checked));
    }

    function disableDoneButton() {
        doneBtnElm.classList.add(doneBtnDisabledClassName);
        doneBtnElm.disabled = true;
    }

    function enableDoneButton() {
        doneBtnElm.classList.remove(doneBtnDisabledClassName);
        doneBtnElm.disabled = false;
    }

    if (!hasAllConsentSelected()) {
        disableDoneButton();
    }

    var handlerFunctionToggle = function(event) {
        event.stopPropagation();
        if (hasAllConsentSelected()) {
            enableDoneButton();
        }
    };

    mailConsentElem.addEventListener("click", handlerFunctionToggle);

    var handlerFunctionAcceptAll = function() {
        event.preventDefault();
        mailFeaturesOptin.checked = true;
        personalizedAdsOptin.checked = true;
        insightsCommOptin.checked = true;
        scrollToBottom();
        enableDoneButton();
    };

    var handlerFunctionDeclineAll = function() {
        event.preventDefault();
        mailFeaturesOptout.checked = true;
        personalizedAdsOptout.checked = true;
        insightsCommOptout.checked = true;
        scrollToBottom();
        enableDoneButton();
    };

    var handlerFunctionScroll = function() {
        if (!footerOptionElem || !scrollContainerElem) {
            return;
        }
        if (scrollContainerElem.scrollHeight - scrollContainerElem.scrollTop <= scrollContainerElem.clientHeight + 5) {
            footerOptionElem.classList.add(hiddenClassName);
        } else {
            footerOptionElem.classList.remove(hiddenClassName);
        }
    };

    if (acceptAllHeaderElem && declineAllHeaderElem) {
        acceptAllHeaderElem.addEventListener(tapEvent, handlerFunctionAcceptAll);
        declineAllHeaderElem.addEventListener(tapEvent, handlerFunctionDeclineAll);
    }
    if (acceptAllFooterElem && declineAllFooterElem) {
        acceptAllFooterElem.addEventListener(tapEvent, handlerFunctionAcceptAll);
        declineAllFooterElem.addEventListener(tapEvent, handlerFunctionDeclineAll);
    }

    if (scrollContainerElem) {
        scrollContainerElem.addEventListener('scroll', handlerFunctionScroll);
    }
}

function handleTooltipInsideExpandableContent () {
    try {
        var tooltipInsideExpandableTxt = document.querySelectorAll('.theme-2.v4 .page-body .expandable-content .expandable-text .info.hover');
        for (var i = 0; i < tooltipInsideExpandableTxt.length; i++) {
            var tooltipElm = tooltipInsideExpandableTxt[i];
            tooltipElm.addEventListener("mouseover", function() {
                if (tooltipElm.hasAttribute('data-tooltip'))  {
                    var controlId = tooltipElm.getAttribute('data-id');
                    var exapndControl = document.getElementById(controlId);
                    if (exapndControl && exapndControl.checked) {
                        exapndControl.checked = false;
                    }
                }
            });

            selectElments[i].checked = newState;
        }
    } catch(e) {
        // this is an enhancement. we dont need to block the experience for any unexpected error.
    }
}

function setupRapid(){
    var rapidComponents = document.querySelectorAll('[data-ylk]');
    if(rapidComponents && rapidComponents.length > 0){
        try {
            rapidComponents.forEach(item => item.addEventListener('click', function () {
                callBeaconClick(item);
            }));
        }catch (e) {
            console.log('failed to call beacon click',e);
        }
    }
    function callBeaconClick(item) {
        try {
            var ylkValueArray = item.dataset.ylk.split(';');
            var ylkValue = ylkValueArray.reduce(function (acc, each) {
                var ylkProp = each.split(':');
                acc[ylkProp[0]] = ylkProp[1];
                return acc;
            }, {})
            if (myRapidInstance) {
                myRapidInstance.beaconClick(ylkValue.sec, ylkValue.slk, 1, ylkValue, 'click', null, null);
            }
        }catch (e) {
            console.log('failed to execute beacon click',e);
        }
    }
}


window.addEventListener( 'pageshow', function ( event ) {
    var historyTraversal = event.persisted ||
        ( typeof window.performance != 'undefined' &&
            window.performance.navigation.type === 2 );
    if ( historyTraversal ) {
        // Handle page restore.
        window.location.reload();
    }
});

window.addEventListener('DOMContentLoaded', function() {
    var langPicker = document.getElementById('consent-lang-picker');
    var consentForm = document.querySelector('.consent-form');
    var footer = document.querySelector('.footer');
    var scrollContainer = document.querySelector('.scroll-container');
    var bodyElement = document.querySelector('body');
    var agreeButton = document.querySelector('.agree');
    var disagreeButton = document.querySelector('.disagree');
    var tapEvent = ('ontouchstart' in document.documentElement) ? 'touchstart' : 'click';
    var isEnterPressed = false;
    var tppToolTipIcons = document.querySelectorAll('.tpp .tool-tip .info-icon');
    var activeTppTollTipElement;
    var singlePageAgreeForm = document.querySelector('.single-page-agree-form');
    var singlePageDisagreeForm = document.querySelector('.single-page-disagree-form');
    var singlePageMoreOptionsForm = document.querySelector('.single-page-more-options-form');
    var isSinglePageFormsPresent = false;
    var scrollDownWrapper = document.querySelector('.scroll-down-wrapper');
    var scrollDownButton = document.getElementById('scroll-down-btn');
    var wizardBody = document.querySelector('.wizard-body');
    var frameworkPartnersWrapper = document.querySelector('.inner-box.tab-controls .tabs');	
    var frameworkPartnersScrollIndicator = document.querySelector('.tab-controls .chevron.scroll-indicator');

    if (agreeButton) {
        agreeButton.disabled = false;
    }

    if (disagreeButton) {
        disagreeButton.disabled = false;
    }

    checkCookie();
    setupBeacon();
    setupTppSelectAll(tapEvent);
    setupTCFVendorDataFetch();
    setupOptinAll(tapEvent);
    selectAllConsentAndLegitAll(tapEvent);
    setupSinglePageExpand(tapEvent);
    setupExperimentalPage(tapEvent);
    setupFakeBgPage(tapEvent);
    togglePurposeAndPartners(tapEvent);
    selectAllFirstPartyDataAll(tapEvent);
    selectAllSocialPartners(tapEvent);
    setMailConsentServicesHoverPosition(tapEvent);
    setMailConsentEventHandler(tapEvent);
    removeClass(document.body, 'no-js');
    addClass(document.body, 'js');
    manageLayerOneCTAState();
    handleTooltipInsideExpandableContent();
    setupRapid();

    detectIE(scrollContainer, footer);

    var scrollHandler = function() {
        if (window.innerHeight + window.pageYOffset + 50 > document.body.scrollHeight) {
            removeClass(scrollContainer, 'active');
            removeClass(footer, 'active');
            window.removeEventListener('scroll', scrollHandler);
        }
    };

    if (bodyElement.clientHeight > window.innerHeight + 100) {
        window.addEventListener('scroll', scrollHandler);
    }

    if (tapEvent === 'click') {
        var tooltipElement = document.querySelector('#consent-text .info.hover');
        if (tooltipElement) {
            tooltipElement.classList.add('touched-once');
        }
    }

    if (tapEvent === 'touchstart') {
        removeClass(document.body, 'no-touch');
        addClass(document.body, 'touch');

        if (tppToolTipIcons) {
            document.body.addEventListener(tapEvent, function(e) {
                if (e.target && Array.prototype.indexOf.call(tppToolTipIcons, e.target) > -1) {
                    if (activeTppTollTipElement) {
                        removeClass(activeTppTollTipElement, 'touch-active');
                    }
                    activeTppTollTipElement = e.target && e.target.parentElement;
                    addClass(activeTppTollTipElement, 'touch-active');
                    return;
                }
                if (activeTppTollTipElement) {
                    removeClass(activeTppTollTipElement, 'touch-active');
                }
            });
        }
    }

    displayScrollToContinue(tapEvent);
    setupEUMoreOptionsToggle(tapEvent);

    if (singlePageAgreeForm) {
        isSinglePageFormsPresent = true;
        singlePageAgreeForm.addEventListener(tapEvent, handleDoubleSubmit);
        singlePageAgreeForm.addEventListener('submit', handleDoubleSubmit);
        singlePageAgreeForm.addEventListener('keydown', function() {
            if (isEnterPressed) {
                event.preventDefault();
                event.stopPropagation();
            }
            if (event.keyCode === 13 || event.keyCode === 10 /* some browser would come with 10 instead of 13 */ ) {
                isEnterPressed = true;
            }
        });
    }

    if (singlePageDisagreeForm) {
        isSinglePageFormsPresent = true;
        singlePageDisagreeForm.addEventListener(tapEvent, handleDoubleSubmit);
        singlePageDisagreeForm.addEventListener('submit', handleDoubleSubmit);
        singlePageDisagreeForm.addEventListener('keydown', function() {
            if (isEnterPressed) {
                event.preventDefault();
                event.stopPropagation();
            }
            if (event.keyCode === 13 || event.keyCode === 10 /* some browser would come with 10 instead of 13 */ ) {
                isEnterPressed = true;
            }
        });
    }

    if (singlePageMoreOptionsForm) {
        isSinglePageFormsPresent = true;
        singlePageMoreOptionsForm.addEventListener(tapEvent, handleDoubleSubmit);
        singlePageMoreOptionsForm.addEventListener('submit', handleDoubleSubmit);
        singlePageMoreOptionsForm.addEventListener('keydown', function() {
            if (isEnterPressed) {
                event.preventDefault();
                event.stopPropagation();
            }
            if (event.keyCode === 13 || event.keyCode === 10 /* some browser would come with 10 instead of 13 */ ) {
                isEnterPressed = true;
            }
        });
    }

    if (consentForm && !isSinglePageFormsPresent) {
        consentForm.addEventListener(tapEvent, handleDoubleSubmit);
        consentForm.addEventListener('submit', handleDoubleSubmit);
        consentForm.addEventListener('keydown', function() {
            if (isEnterPressed) {
                event.preventDefault();
                event.stopPropagation();
            }
            if (event.keyCode === 13 || event.keyCode === 10 /* some browser would come with 10 instead of 13 */ ) {
                isEnterPressed = true;
            }
        });
    }

    if (langPicker) {
        langPicker.addEventListener('change', onLanguageChange);
    }

    if (scrollDownWrapper && scrollDownButton && wizardBody && consentForm) {
        function scrollDownButtonShouldAppear() {
            if((wizardBody.scrollHeight > wizardBody.clientHeight)
                && (wizardBody.scrollTop === 0)) {
                addClass(scrollDownWrapper, 'show');
            } else {
                removeClass(scrollDownWrapper, 'show');
            }
        }
        scrollDownButtonShouldAppear();
        window.addEventListener('resize', scrollDownButtonShouldAppear);
        scrollDownButton.addEventListener('click', function handleScrollDown() {
            if('scrollBehavior' in document.documentElement.style) {
                wizardBody.scrollTo({
                    top:  wizardBody.scrollHeight,
                    behavior: 'smooth'
                 });
            } else {
                wizardBody.scrollTo(0,  wizardBody.scrollHeight);
            }
            removeClass(scrollDownWrapper, 'show');
            window.removeEventListener('resize', scrollDownButtonShouldAppear);
        });
        var wizardBodyScrollDown = function() {
            removeClass(scrollDownWrapper, 'show');
            wizardBody.removeEventListener('scroll', wizardBodyScrollDown);
            window.removeEventListener('resize', scrollDownButtonShouldAppear);
        }
        wizardBody.addEventListener('scroll', wizardBodyScrollDown)
    }

    if(frameworkPartnersWrapper && frameworkPartnersScrollIndicator) {	
        var hasHorizontalScrollbar = frameworkPartnersWrapper.scrollWidth > frameworkPartnersWrapper.clientWidth;

        if (hasHorizontalScrollbar) {
            removeClass(frameworkPartnersScrollIndicator, 'hide');	
            var tabScroll = function() {	
                addClass(frameworkPartnersScrollIndicator, 'hide');	
                frameworkPartnersWrapper.removeEventListener('scroll', tabScroll);	
            }	
            frameworkPartnersWrapper.addEventListener('scroll', tabScroll)
        }
    }

    /**
    * This method sets display to none on the tooltipV2 container making it disappear.
    **/
    var closeTooltipV2WhichAreOpen = function() {
        document.querySelectorAll(".info-popup").forEach(function(tooltipV2Element) {
            if (tooltipV2Element.style.display !== 'none') {
                tooltipV2Element.style.display = 'none';
            }
        });
    }

    /**
    * This method acts as a hover tooltip span's on click event handler. This method modifies the width of the
    * tooltip v2 based on screen's width to make sure the tooltip v2 is responsive.
    **/
    var hoverSpanElementOnClick = function(event) {
        // There is a possibility that two hover spans in one page could be clicked one after an other. This will cause
        // the two tooltips to be opened. In order to resolve this issue, we initially set the display attribute of
        // all the tooltips in the page to none.
        closeTooltipV2WhichAreOpen();

        var hoverSpanElement = event.target;
        var tooltipPopupV2Element = hoverSpanElement.querySelector(".info-popup");

        if (!tooltipPopupV2Element) {
            return;
        }

        // Get the span element's and its parent's bounding client rect for tooltip v2 responsive width calculations.
        var hoverSpanElementBoundingClientRect = hoverSpanElement.getBoundingClientRect();
        var hoverSpanElementParentNode = hoverSpanElement.parentNode;
        var hoverSpanElementParentNodeBoundingClientRect = hoverSpanElementParentNode.getBoundingClientRect();
        // We need the difference between the parent and the child's x to place the tooltip at the beginning of the page
        var spanToParentXDiff = hoverSpanElementBoundingClientRect.x - hoverSpanElementParentNodeBoundingClientRect.x;
        var hoverSpanElementParentNodeStyles = window.getComputedStyle(hoverSpanElementParentNode);
        // Some parent elements have padding left which needs to be considered for better tooltip alignment.
        var hoverSpanElementParentNodeStyleLeftValue = hoverSpanElementParentNodeStyles.getPropertyValue('padding-left');
        // Setting the left / x of the new tooltip element so that its placed just below the span
        tooltipPopupV2Element.style.left = `-${spanToParentXDiff - parseInt(hoverSpanElementParentNodeStyleLeftValue, 10)}px`;
        tooltipPopupV2Element.style.display = 'flex';
    }

    /**
    * Each span element in the page is iterated over so that we could add few event listeners or style attributes. This
    * is a callback function for the forEach.
    **/
    var spanHoverForEachElementCallbackFn = function(spanElement) {
        spanElement.onclick = hoverSpanElementOnClick;
        var tooltipPopupV2Element = spanElement.querySelector(".info-popup");

        if (!tooltipPopupV2Element) {
            return;
        }

        tooltipPopupV2Element.onclick = function(tooltipV2ElementClickEvent) {
            tooltipV2ElementClickEvent.stopPropagation();
        }

        var tooltipPopupV2ElementCloseButton = tooltipPopupV2Element.querySelector(".info-popup-content > img");

        if (tooltipPopupV2ElementCloseButton) {
            tooltipPopupV2ElementCloseButton.onclick = function() {
                tooltipPopupV2Element.style.display = 'none';
            };
        }
    }

    /**
    * This method is an event handler for user outside click action on any UI component in the current page.
    * This can be used as a on outside click for the new tooltip popup v2. The reason for this is if a user clicks
    * outside the containing tooltip data, the tooltip should disappear.
    **/
    var windowDocumentOnClick = function(event) {
        var clickedElementClassName = event.target.className;

        // If user clicks anywhere apart from the <span class="info hover"/> , remove the tooltip.
        var tooltipV2WhitelistedClasses = ["info-popup", "info-popup-content", "info-popup-heading", "info-popup-description"]
        if (!clickedElementClassName.includes("info hover") && !tooltipV2WhitelistedClasses.includes(clickedElementClassName)) {
            closeTooltipV2WhichAreOpen();
        }
    }

    var newTooltipPopupV2Element = document.querySelector("#consent-page.theme-2 .info[data-tooltip] .info-popup");

    if (newTooltipPopupV2Element) {
        document.onclick = windowDocumentOnClick;
        document.querySelectorAll("#consent-page.theme-2 .info[data-tooltip]")
                .forEach(spanHoverForEachElementCallbackFn);
        // TODO : Post stage test of TooltipV2, take a look at consentV4.hbs , partnersV4.hbs and mailbox.hbs
        // TODO and remove the styles and move it to style.css for the new tooltip implementation
    }

    var windowDocumentOnClickForunderAge = function(event) {
        var clickedElementClassName = event.target.className;
        var clickedParentElementClassName = event.target.parentElement.className;

        // If user clicks anywhere apart from the <span class="info hover"/> , remove the tooltip.
        var tooltipV2WhitelistedClasses = ["info-popup", "info-popup-content", "info-popup-heading", "info-popup-description"]
        if (!(clickedElementClassName.includes("underage-info-popup") || clickedParentElementClassName.includes("underage-info-popup")) && !tooltipV2WhitelistedClasses.includes(clickedElementClassName)) {
            closeTooltipV2WhichAreOpen();
        }
    }


    /**
     * This method acts as a hover tooltip span's on click event handler. This method modifies the width of the
     * tooltip v2 based on screen's width to make sure the tooltip v2 is responsive.
     **/
    var hoverSpanElementOnClickForUnderage = function(event) {
        // There is a possibility that two hover spans in one page could be clicked one after an other. This will cause
        // the two tooltips to be opened. In order to resolve this issue, we initially set the display attribute of
        // all the tooltips in the page to none.
        closeTooltipV2WhichAreOpen();
        var tooltipPopupV2Element = event.target.parentNode.querySelector(".info-popup");

        if (!tooltipPopupV2Element) {
            return;
        }

        // Get the span element's and its parent's bounding client rect for tooltip v2 responsive width calculations.
        tooltipPopupV2Element.style.left = '0px';
        tooltipPopupV2Element.style.display = 'flex';
        var left = tooltipPopupV2Element.parentElement.getBoundingClientRect().right - tooltipPopupV2Element.getBoundingClientRect().right;
        if (window.innerWidth <= 950) {
            if (event.target.parentNode.classList.contains('underage-info-mobile-center')) {
                left = left / 2;
            } else {
                left = tooltipPopupV2Element.parentElement.parentElement.parentElement.parentElement.getBoundingClientRect().right - window.innerWidth;
            }
        }
        tooltipPopupV2Element.style.left = `${left}px`;
    }

    /**
     * Each span element in the page is iterated over so that we could add few event listeners or style attributes. This
     * is a callback function for the forEach.
     **/
    var spanHoverForEachElementCallbackFnForUnderage = function(spanElement) {
        spanElement.onclick = hoverSpanElementOnClickForUnderage;
        spanElement.onmouseover = hoverSpanElementOnClickForUnderage;
        var tooltipPopupV2Element = spanElement.querySelector(".info-popup");

        if (!tooltipPopupV2Element) {
            return;
        }

        tooltipPopupV2Element.onclick = function(tooltipV2ElementClickEvent) {
            tooltipV2ElementClickEvent.stopPropagation();
        }

        tooltipPopupV2Element.onmouseover = function(tooltipV2ElementEvent) {
            tooltipV2ElementEvent.stopPropagation();
        }

        var tooltipPopupV2ElementCloseButton = tooltipPopupV2Element.querySelector(".info-popup-content > img");

        if (tooltipPopupV2ElementCloseButton) {
            tooltipPopupV2ElementCloseButton.onclick = function() {
                tooltipPopupV2Element.style.display = 'none';
            };
        }
    }

    var newTooltipPopupUnderageElement = document.querySelector(".underage-info-popup .info-popup");

    if (newTooltipPopupUnderageElement) {
        document.onclick = windowDocumentOnClickForunderAge;
        document.querySelectorAll(".underage-info-popup")
            .forEach(spanHoverForEachElementCallbackFnForUnderage);
        // TODO : Post stage test of TooltipV2, take a look at consentV4.hbs , partnersV4.hbs and mailbox.hbs
        // TODO and remove the styles and move it to style.css for the new tooltip implementation
    }
});

},{}],3:[function(require,module,exports){

function timerFunctionality() {
    let remaining = 20;
    if(document.getElementById('login-form-resend-code')) {
        var timerClear = setInterval(function() {
            if(remaining >= 0) {
                document.getElementById('login-form-resend-code').innerHTML = remaining;
                remaining--;
            } else {
                clearInterval(timerClear);
                document.getElementById('timer-off-details').classList.remove('hide-content');
                document.getElementById('login-form-resend-code-complete').classList.add('hide-content');
            }
        }, 1000);
    }
}

function errorMessageCSSAdd() {
    if(document.getElementById('error-message-text')) {
        document.getElementById('data-naiOptOut-phone-input').classList.add('error-message');
        document.getElementById('mobileNumberError').classList.remove('hidden');
    }
}

function otpAutoFill() {
    if(document.getElementById('nai-form-otp')) {
        var container = document.getElementsByClassName("container-otp")[0];
        container.onkeyup = function(e) {
            var target = e.srcElement;
            var maxLength = parseInt(target.attributes["maxlength"].value, 10);
            var myLength = target.value.length;
            if (myLength >= maxLength) {
                var next = target;
                while (next = next.nextElementSibling) {
                    if (next == null)
                        break;
                    if (next.tagName.toLowerCase() == "input") {
                        next.focus();
                        break;
                    }
                }
            }
        }
    }
}

function checkEmailValidationYahooConnectID(tapEvent) {
    if(document.getElementById('nai-form')) {
        let nextBtnElm = document.querySelector('.nai-form .btnNext');
        let errorMsgElm = document.querySelector('.nai-form .error-msg');
        let emailInputElem = document.querySelector('.nai-form .txtEmail');
        let doneBtnDisabledClassName = 'done-btn-disabled';
        let hiddenClassName = 'hidden'
        nextBtnElm.classList.add(doneBtnDisabledClassName);
        nextBtnElm.disabled = true;
        if(document.getElementById('email').checked == true || window.getComputedStyle(emailInputElem).display !== 'none') {
            let emailFormat = /^([0-9a-zA-Z_\-\.])+\@([0-9a-zA-Z_\-\.])+\.([a-zA-Z]{2,4})$/;
            if (emailInputElem) {
                emailInputElem.addEventListener('input', function () {
                    let emailValue = emailInputElem.value;
                    if (emailValue && emailValue.match(emailFormat)) {
                        errorMsgElm.classList.add(hiddenClassName);
                        nextBtnElm.classList.remove(doneBtnDisabledClassName);
                        nextBtnElm.disabled = false;
                    } else if (emailValue && !emailValue.match(emailFormat)) { // shows error message when value doesn't match
                        errorMsgElm.classList.remove(hiddenClassName);
                        nextBtnElm.classList.add(doneBtnDisabledClassName);
                        nextBtnElm.disabled = true;
                    } else { // shows no error message when the field is empty
                        errorMsgElm.classList.add(hiddenClassName);
                        nextBtnElm.classList.add(doneBtnDisabledClassName);
                        nextBtnElm.disabled = true;
                    }
                });
            }
        } else {
            let phoneInputElem = document.querySelector('.nai-form .txtPhone');
            let phoneCodeinputElem = document.getElementById('data-naiOptOut-country-code-input');
            if(phoneInputElem) {
                phoneInputElem.addEventListener('input', function () {
                    let phoneValue = phoneInputElem.value;
                    let countryCodeVale = phoneCodeinputElem.value;
                    if (phoneValue && countryCodeVale) {
                        errorMsgElm.classList.add(hiddenClassName);
                        nextBtnElm.classList.remove(doneBtnDisabledClassName);
                        nextBtnElm.disabled = false;
                    } else {
                        nextBtnElm.classList.add(doneBtnDisabledClassName);
                        nextBtnElm.disabled = true;
                    }
                });
            }
            if(phoneCodeinputElem) {
                phoneCodeinputElem.addEventListener('input', function () {
                    let countryCodeVale = phoneCodeinputElem.value;
                    if (phoneValue && countryCodeVale) {
                        errorMsgElm.classList.add(hiddenClassName);
                        nextBtnElm.classList.remove(doneBtnDisabledClassName);
                        nextBtnElm.disabled = false;
                    } else {
                        nextBtnElm.classList.add(doneBtnDisabledClassName);
                        nextBtnElm.disabled = true;
                    }
                });
                phoneCodeinputElem.addEventListener('keydown', function(event) {
                    const key = event.key; // const {key} = event; ES6+
                    if (key === "Backspace" || key === "Delete") {
                        phoneCodeinputElem.value = "";
                        nextBtnElm.classList.add(doneBtnDisabledClassName);
                        nextBtnElm.disabled = true;
                    }
                });
            }
        }
    }
}

function checkModeOfCommChange(tapEvent) {
    if(document.getElementById('nai-form')) {
        let radioInputs = document.querySelectorAll('input[name=modeOfComm]');
        if(radioInputs) {
            radioInputs.forEach(function(radio) {
              radio.addEventListener('change', function () {
                    checkEmailValidationYahooConnectID(tapEvent);
              });
            });
            checkEmailValidationYahooConnectID(tapEvent);
        }
    }
}

function otpValidateOnSubmit(tapEvent) {
    if(document.getElementById('nai-form-otp')) {
        var container = document.getElementsByClassName("container-otp")[0];
        var nextBtnElm = document.querySelector('#nai-form-otp .submitOTPScreen');
        var errorMsgElm = document.querySelector('#nai-form-otp .otp-error-msg');
        let doneBtnDisabledClassName = 'done-btn-disabled';
        let hiddenClassName = 'hidden'
        nextBtnElm.classList.add(doneBtnDisabledClassName);
        nextBtnElm.disabled = true;
        container.addEventListener('keyup', function() {
            errorMsgElm.classList.add(hiddenClassName);
            nextBtnElm.classList.remove(doneBtnDisabledClassName);
            nextBtnElm.disabled = false;
            container.querySelectorAll('input').forEach((each) => {
                if(!each.value) {
                    nextBtnElm.classList.add(doneBtnDisabledClassName);
                    nextBtnElm.disabled = true;
                }
            });
        });
        nextBtnElm.addEventListener(tapEvent, function() {
            container.querySelectorAll('input').forEach((each) => {
                if(!each.value) {
                    errorMsgElm.classList.remove(hiddenClassName);
                }
                else {
                    errorMsgElm.classList.add(hiddenClassName);
                }
            });
        });
    }
}

window.addEventListener('DOMContentLoaded', function() {
    var tapEvent = ('ontouchstart' in document.documentElement) ? 'touchstart' : 'click';

    timerFunctionality();
    errorMessageCSSAdd();
    otpAutoFill();
    otpValidateOnSubmit(tapEvent);
    checkModeOfCommChange(tapEvent);
});
},{}],4:[function(require,module,exports){
'use strict';

function blockingConsentPopupGoToTheEnd(wizardBodyId) {
    var scrollDownWrapper = document.querySelector('.scroll-down-wrapper');
    var scrollDownButton = document.getElementById('scroll-down-btn');
    var wizardBody = document.getElementById(wizardBodyId);

    if (scrollDownWrapper && scrollDownButton && wizardBody) {
        function scrollDownButtonShouldAppear() {
            if((wizardBody.scrollHeight > wizardBody.clientHeight)
              && (wizardBody.scrollTop === 0)) {
                scrollDownWrapper.classList.add('show');
            } else {
                scrollDownWrapper.classList.remove('show');
            }
        }

        scrollDownButtonShouldAppear();

        window.addEventListener('resize', scrollDownButtonShouldAppear);
        scrollDownButton.addEventListener('click', function handleScrollDown() {
            if('scrollBehavior' in document.documentElement.style) {
                wizardBody.scrollTo({
                    top:  wizardBody.scrollHeight,
                    behavior: 'smooth'
                });
            } else {
                wizardBody.scrollTo(0,  wizardBody.scrollHeight);
            }

            scrollDownWrapper.classList.remove('show');
            window.removeEventListener('resize', scrollDownButtonShouldAppear);
        });

        var wizardBodyScrollDown = function() {
            scrollDownWrapper.classList.remove('show');
            wizardBody.removeEventListener('scroll', wizardBodyScrollDown);
            window.removeEventListener('resize', scrollDownButtonShouldAppear);
        }

        wizardBody.addEventListener('scroll', wizardBodyScrollDown)
    }
}

function personalizedAdsCAPostCrossFrameMessage(oathGUCEIframeConsentOptions) {
    var formElement = window.OathGUCEIframe.consent(oathGUCEIframeConsentOptions);

    var personalizedAdsCAAllow = document.getElementById("login-form-personalized-ads-ca-allow");
    if(personalizedAdsCAAllow) {
        personalizedAdsCAAllow.addEventListener('click', function() {
            formElement.postCrossFrameMessage({messageType: "invokeCTA"});
        });
    }

    var personalizedAdsCADoNotAllow = document.getElementById("login-form-personalized-ads-ca-donotallow");
    if(personalizedAdsCADoNotAllow) {
        personalizedAdsCADoNotAllow.addEventListener('click', function() {
            formElement.postCrossFrameMessage({messageType: "secondaryCTA"});
        });
    }

    var personalizedAdsCAAskMeLater = document.getElementById("login-form-personalized-ads-ca-askmelater");
    if(personalizedAdsCAAskMeLater) {
        personalizedAdsCAAskMeLater.addEventListener('click', function() {
            formElement.postCrossFrameMessage({messageType: "invokeAskMeLater"});
        });
    }

    var closeButton = document.getElementById("close-button");
    if(closeButton) {
        closeButton.addEventListener('click', function() {
            formElement.postCrossFrameMessage({messageType: "invokeClose"});
        });
    }
}
},{}],5:[function(require,module,exports){
'use strict';

function callBeaconClick(ylkValue) {
     if (window.myRapidInstance) {
       window.myRapidInstance.beaconClick(ylkValue.sec, ylkValue.slk, 1, ylkValue, 'click', function(){}, {});
     }
}

function getYlkParameterFromEventAttribute(event) {
    var ylkValueString = event.target.getAttribute('data-ylk');
    if(ylkValueString){
    var ylkValueArray = ylkValueString.split(';');
    return ylkValueArray.reduce(function (acc, each) {
         var ylkProp = each.split(':');
         acc[ylkProp[0]] = ylkProp[1];
         return acc;
     }, {});
    }
    return null;
}

window.addEventListener('DOMContentLoaded', function() {
    var editConsentToggleSwitch = document.querySelector('.edit-radio-toggle-switch'),
        editButtonGoBack = document.querySelector('.modal-btn-go-back'),
        editCoreConsentModal = document.querySelector('.core-consent-modal'),
        editCoreConsentRemoveLink = document.querySelector('.edit-core-consent-remove-link'),
        editConsentWizardForms = document.querySelectorAll('.edit-consent-wizard-form'),
        stateCheck = document.querySelector(".state-check"),
        privacyChoicesGroup = document.querySelector('.state-controls-group'),
        privacyMobileNavButton = document.querySelector('.site-mobile-nav');

    if (editConsentWizardForms.length === 1) {
        editConsentToggleSwitch.addEventListener('change', function() {
            var editConsentWizardForm = document.querySelector('.edit-consent-wizard-form'),
                editConsentEventType = document.getElementById('consent-type-event');
            if (editConsentEventType.value === 'coreConsent' && this.checked === false) {
                //Show core consent modal
                if(editCoreConsentModal) {
                    editCoreConsentModal.style.display = 'block';
                }
            } else {
                if (editConsentWizardForm) {
                    addProcessingSpinner();
                    editConsentWizardForm.submit();
                }
            }
        });
    }
    if(stateCheck) {
        stateCheck.addEventListener('change', function() {
                var toggleButton = event.target;
                if (!toggleButton.hasAttribute('data-event-type')) {
                    return;
                }
                addProcessingSpinner();
                var eventType = toggleButton.getAttribute("data-event-type");
                var form = document.querySelector(".edit-consent-wizard-form-" + eventType);
                var ylkValue = getYlkParameterFromEventAttribute(event);

                if (ylkValue) {
                     callBeaconClick(ylkValue); // Pass ylkValue to callBeaconClick
                }
                form.submit();
            });
    }
    else {
        var editConsentGroup = document.querySelector(".edit-consent-wizard.edit-consent-group");
        if (editConsentGroup) {
            editConsentGroup.addEventListener('change', function() {
                var toggleButton = event.target;
                if (!toggleButton.hasAttribute('data-event-type')) {
                    return;
                }
                addProcessingSpinner();
                var eventType = toggleButton.getAttribute("data-event-type");
                var form = document.querySelector(".edit-consent-wizard-form." + eventType);
                form.submit();

            });
        }
    }

    if (privacyChoicesGroup) {
        privacyChoicesGroup.addEventListener('change', function() {
            var toggleButton = event.target;
            var eventType = toggleButton.getAttribute("data-event-type");
            if (!eventType) {
                return;
            }
            addProcessingSpinner();
            var ylkValue = getYlkParameterFromEventAttribute(event);
            if(ylkValue) {
            callBeaconClick(ylkValue); // Pass ylkValue to callBeaconClick
            }
            var form = document.querySelector(".state-consent-control-wizard-form." + eventType);
            form.submit();
        });
    }

    if(privacyMobileNavButton) {
        privacyMobileNavButton.addEventListener('click', function(){
            var mobileMenu = document.querySelector('.privacy-centre-mobile-menu');
            mobileMenu.classList.remove('hidden');
            document.getElementById('edit-section').classList.add('hidden');
            privacyMobileNavButton.classList.add('hidden');
        });
        var privacyCentreNavCloseButton = document.querySelector('button.btn-close');
        if(privacyCentreNavCloseButton) {
            privacyCentreNavCloseButton.addEventListener('click', function(){
                var mobileMenu = document.querySelector('.privacy-centre-mobile-menu');
                mobileMenu.classList.add('hidden');
                document.getElementById('edit-section').classList.remove('hidden');
                privacyMobileNavButton.classList.remove('hidden');
            });
        }
        var privacyCentreSubMenuBackButton = document.querySelectorAll('.pc-submenu-back');
        const outerHeading = document.getElementById("privacy-states");

        if (privacyCentreSubMenuBackButton) {
            for(let elem of privacyCentreSubMenuBackButton) {
                elem.addEventListener('click', function(){
                  if (outerHeading.classList.contains("hidden")) {
                      document.getElementById('menu-primary-navigation').classList.remove('menu-submenu-active');
                      elem.parentElement.classList.add('hidden');
                      document.getElementById('pc-menu-btn-close').classList.remove('hidden');
                  } else {
                      document.querySelectorAll(".privacy-centre").forEach(heading => heading.classList.remove("hidden"));
                      document.getElementById('privacy-states').classList.add('hidden');
                   }
                });
            }
        }

        var privacyCentreSubMenuOpenButton = document.querySelectorAll('li.menu-parent > div.line-wrap');

        if (privacyCentreSubMenuOpenButton) {
            for(let elem of privacyCentreSubMenuOpenButton) {
                elem.addEventListener('click', function(){
                    document.getElementById('menu-primary-navigation').classList.add('menu-submenu-active');
                    elem.nextElementSibling.classList.remove('hidden');
                    document.getElementById('pc-menu-btn-close').classList.add('hidden');
                });
            }
        }

        var privacyCentreSubMenuOpenButton = document.querySelectorAll('div.state-privacy-menu');

        if (privacyCentreSubMenuOpenButton) {
            for(let elem of privacyCentreSubMenuOpenButton) {
               elem.addEventListener('click', function(){
                   document.getElementById('menu-primary-navigation').classList.add('menu-submenu-active');
                   elem.nextElementSibling.classList.remove('hidden');
                   document.querySelectorAll(".privacy-centre").forEach(heading => heading.classList.add("hidden"));
               });
            }
        }
    }

    if (editCoreConsentRemoveLink) {
        editCoreConsentRemoveLink.addEventListener('click', function() {
            var editCoreConsentRemoveForm = document.querySelector('.edit-core-consent-remove-form');
            if(editCoreConsentRemoveForm) {
                addProcessingSpinner();
                editCoreConsentRemoveForm.submit();
            }
        });
    }
    var editButtonAnchor = document.querySelector('.core-consent-modal-anchor'),
        editModalCloseSpan = document.querySelector('.modal-close');
    if (editButtonAnchor) {
        editButtonAnchor.addEventListener('click', function() {
            if(editCoreConsentModal) {
                editCoreConsentModal.style.display = 'block';
            }
        });
    }
    if (editModalCloseSpan) {
        editModalCloseSpan.addEventListener('click', function() {
            if(editCoreConsentModal) {
                editCoreConsentModal.style.display = 'none';
            }
        });
    }
    window.onclick = function(event) {
        if (event.target == editCoreConsentModal || event.target == editButtonGoBack) {
            editConsentToggleSwitch.checked = true;
            editCoreConsentModal.style.display = 'none';
        }
    };
});

function addProcessingSpinner() {
    var throbberSection = document.getElementById('throbber-section'),
        editSection = document.getElementById('edit-section'),
        editBackHeaderBox = document.getElementById('edit-back-header-box');

    if (throbberSection) { throbberSection.classList.remove('hidden'); }
    if (editSection) { editSection.classList.add('hidden'); }
    if (editBackHeaderBox) { editBackHeaderBox.classList.add('hidden'); }
}
},{}]},{},[1,2,3,4,5]);
