/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import Foundation
import WebKit
import Shared

private let log = Logger.browserLogger

extension WKNavigationAction {
    /// Allow local requests only if the request is privileged.
    var isAllowed: Bool {
        guard let url = request.url else {
            return true
        }

        return !url.isWebPage(includeDataURIs: false) || !url.isLocal || request.isPrivileged
    }
}

extension BrowserViewController: WKNavigationDelegate {
    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        if tabManager.selectedTab?.webView !== webView {
            return
        }

        updateFindInPageVisibility(visible: false)

        // If we are going to navigate to a new page, hide the reader mode button. Unless we
        // are going to a about:reader page. Then we keep it on screen: it will change status
        // (orange color) as soon as the page has loaded.
        if let url = webView.url {
            if !url.isReaderModeURL {
                urlBar.updateReaderModeState(ReaderModeState.unavailable)
                hideReaderModeBar(animated: false)
            }

            // remove the open in overlay view if it is present
            removeOpenInView()
        }
    }

    // Recognize an Apple Maps URL. This will trigger the native app. But only if a search query is present. Otherwise
    // it could just be a visit to a regular page on maps.apple.com.
    fileprivate func isAppleMapsURL(_ url: URL) -> Bool {
        if url.scheme == "http" || url.scheme == "https" {
            if url.host == "maps.apple.com" && url.query != nil {
                return true
            }
        }
        return false
    }

    // Recognize a iTunes Store URL. These all trigger the native apps. Note that appstore.com and phobos.apple.com
    // used to be in this list. I have removed them because they now redirect to itunes.apple.com. If we special case
    // them then iOS will actually first open Safari, which then redirects to the app store. This works but it will
    // leave a 'Back to Safari' button in the status bar, which we do not want.
    fileprivate func isStoreURL(_ url: URL) -> Bool {
        if url.scheme == "http" || url.scheme == "https" {
            if url.host == "itunes.apple.com" {
                return true
            }
        }
        return false
    }

    // This is the place where we decide what to do with a new navigation action. There are a number of special schemes
    // and http(s) urls that need to be handled in a different way. All the logic for that is inside this delegate
    // method.

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(WKNavigationActionPolicy.cancel)
            return
        }

        if url.scheme == "about" {
            decisionHandler(WKNavigationActionPolicy.allow)
            return
        }

        if !navigationAction.isAllowed && navigationAction.navigationType != .backForward {
            log.warning("Denying unprivileged request: \(navigationAction.request)")
            decisionHandler(WKNavigationActionPolicy.cancel)
            return
        }

        // First special case are some schemes that are about Calling. We prompt the user to confirm this action. This
        // gives us the exact same behaviour as Safari.
        if url.scheme == "tel" || url.scheme == "facetime" || url.scheme == "facetime-audio" {
            UIApplication.shared.openURL(url)
            decisionHandler(WKNavigationActionPolicy.cancel)
            return
        }

        // Second special case are a set of URLs that look like regular http links, but should be handed over to iOS
        // instead of being loaded in the webview. Note that there is no point in calling canOpenURL() here, because
        // iOS will always say yes. TODO Is this the same as isWhitelisted?

        if isAppleMapsURL(url) {
            UIApplication.shared.openURL(url)
            decisionHandler(WKNavigationActionPolicy.cancel)
            return
        }

        if let tab = tabManager.selectedTab, isStoreURL(url) {
            decisionHandler(WKNavigationActionPolicy.cancel)

            let alreadyShowingSnackbarOnThisTab = tab.bars.count > 0
            if !alreadyShowingSnackbarOnThisTab {
                TimerSnackBar.showAppStoreConfirmationBar(forTab: tab, appStoreURL: url)
            }

            return
        }

        // Handles custom mailto URL schemes.
        if url.scheme == "mailto" {
            if let mailToMetadata = url.mailToMetadata(), let mailScheme = self.profile.prefs.stringForKey(PrefsKeys.KeyMailToOption), mailScheme != "mailto" {
                self.mailtoLinkHandler.launchMailClientForScheme(mailScheme, metadata: mailToMetadata, defaultMailtoURL: url)
            } else {
                UIApplication.shared.openURL(url)
            }

            LeanplumIntegration.sharedInstance.track(eventName: .openedMailtoLink)
            decisionHandler(WKNavigationActionPolicy.cancel)
            return
        }
        
        //Version Qwant Junior
        if (url.host != nil) {
            print("URL Host : " + url.host!)
            print("URL : " + url.absoluteString)

            if (navigationAction.navigationType == WKNavigationType.backForward ) {
                print("WKNavigationType.backForward")
            } else if (navigationAction.navigationType == WKNavigationType.formResubmitted ) {
                print("WKNavigationType.formResubmitted")
            } else if (navigationAction.navigationType == WKNavigationType.formSubmitted ) {
                print("WKNavigationType.formSubmitted")
            } else if (navigationAction.navigationType == WKNavigationType.linkActivated ) {
                print("WKNavigationType.linkActivated")
            } else if (navigationAction.navigationType == WKNavigationType.other ) {
                print("WKNavigationType.other")
            } else if (navigationAction.navigationType == WKNavigationType.reload ) {
                print("WKNavigationType.reload")
            }
            
            if (url.host! == "localhost" && url.absoluteString.range(of: "The%20Internet%20connection%20appears%20to%20be%20offline") != nil) {
                decisionHandler(WKNavigationActionPolicy.cancel)
                webView.loadHTMLString(GameOffline.sharedInstance.code, baseURL: nil)
                return
            }
            
            if (!BlackListSingleton.sharedInstance.isQwantJuniorHost(hostTesting: url.host!)) {
                
                if (BlackListSingleton.sharedInstance.isRedirect(hostTesting: url.host!, onResponse: { (res : Bool) in
                    if (res) {
                        decisionHandler(WKNavigationActionPolicy.cancel)
                    }
                }, onTimeout : {
                    decisionHandler(WKNavigationActionPolicy.cancel)
                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getTimeoutUrl())!))
                })) {
                    return
                }
                if (BlackListSingleton.sharedInstance.isRedirect(urlTesting: url.absoluteString, onResponse: { (res : Bool) in
                    if (res) {
                        decisionHandler(WKNavigationActionPolicy.cancel)
                    }
                }, onTimeout : {
                    decisionHandler(WKNavigationActionPolicy.cancel)
                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getTimeoutUrl())!))
                })) {
                    return
                }
                if (BlackListSingleton.sharedInstance.isBlackListed(hostTesting: url.host!, onResponse: { (res : Bool) in
                    if (res) {
                        decisionHandler(WKNavigationActionPolicy.cancel)
                        webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getWarningUrl())!))
                    }
                }, onTimeout : {
                    decisionHandler(WKNavigationActionPolicy.cancel)
                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getTimeoutUrl())!))
                })) {
                    return
                }
                if (BlackListSingleton.sharedInstance.isBlackListed(urlTesting: url.absoluteString, onResponse: { (res : Bool) in
                    if (res) {
                        decisionHandler(WKNavigationActionPolicy.cancel)
                        webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getWarningUrl())!))
                    }
                }, onTimeout : {
                    decisionHandler(WKNavigationActionPolicy.cancel)
                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getTimeoutUrl())!))
                })) {
                    return
                }
                if (BlackListSingleton.sharedInstance.isIp(hostTesting: url.host!)) {
                    
                    decisionHandler(WKNavigationActionPolicy.cancel)
                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getIpUrl())!))
                    return
                }
                if (urlBar.currentURL?.host == url.host || navigationAction.navigationType == WKNavigationType.linkActivated ) {
                    let searchEngine = BlackListSingleton.sharedInstance.findSearchEngineName(hostTesting: url.host!)
                    if (searchEngine != nil) {
                        
                        if (!BlackListSingleton.sharedInstance.searchEngineHasValidState(searchEngineName: searchEngine!)) {
                            decisionHandler(WKNavigationActionPolicy.cancel)
                            webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getWarningSearchEngineUrl())!))
                            return
                        }
                        if (BlackListSingleton.sharedInstance.isFirstSearchEngine(hostTesting: url.host!)) {
                            
                            decisionHandler(WKNavigationActionPolicy.cancel)
                            webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getSearchEngineUrl(url.host!))!))
                            return
                        }
                        
                        if (BlackListSingleton.sharedInstance.searchEngineHasSafeSearchUrlAvailable(searchEngineName: searchEngine!, url: url.absoluteString)) {
                            if (!BlackListSingleton.sharedInstance.searchEngineHasSafeSearchUrl(searchEngineName: searchEngine!, url: url.absoluteString)) {
                                decisionHandler(WKNavigationActionPolicy.cancel)
                                webView.load(URLRequest(url: URL(string: BlackListSingleton.sharedInstance.convertSearchEngineSafeSearchUrl(searchEngineName: searchEngine!, url: url.absoluteString))!))
                            }
                        } else if (BlackListSingleton.sharedInstance.searchEngineHasSafeSearchRequestAvailable(searchEngineName: searchEngine!)) {
                            BlackListSingleton.sharedInstance.runSearchEngineSafeSearchRequest(searchEngineName: searchEngine!)
                        } else {
                            if (BlackListSingleton.sharedInstance.searchEngineHasSearch(searchEngineName: searchEngine!, url: url.absoluteString)) {
                                if (BlackListSingleton.sharedInstance.searchInSearchEngineIfBlacklistedResult(searchEngineName: searchEngine!, url: url.absoluteString)) {
                                    decisionHandler(WKNavigationActionPolicy.cancel)
                                    webView.load(URLRequest(url: URL(string : BlackListSingleton.sharedInstance.getWarningUrl())!))
                                    return
                                }
                            }
                        }
                    }
                    //YOUTUBE SAFE SEARCH
                    let youtubeDomainRegex = try! NSRegularExpression(pattern : "(www\\.)?youtube(\\.[a-z]+)+", options: [])
                    if (youtubeDomainRegex.numberOfMatches(in: url.host!, options: [], range: NSRange(location: 0, length: url.host!.count)) != 0) {
                        if (!url.absoluteString.contains("safe=active")) {
                            decisionHandler(WKNavigationActionPolicy.cancel)
                            var youtubeUrl = url.absoluteString
                            if youtubeUrl.contains("?") {
                                youtubeUrl = youtubeUrl + "&" + "safe=active"
                            } else {
                                youtubeUrl = youtubeUrl + "?" + "safe=active"
                            }
                            print("url youtube : \(url)")
                            var request = URLRequest(url: URL(string : youtubeUrl )! )
                            request.addValue("PREF=f1=50000000&f2=8000000", forHTTPHeaderField: "Cookie")
                            webView.load(request);
                        }
                    }
                }
            }
            
            /*webView.evaluateJavaScript("document.documentElement.outerHTML", completionHandler: { (html, err) in
                print("---> \(html)")
            })*/
        }

        // This is the normal case, opening a http or https url, which we handle by loading them in this WKWebView. We
        // always allow this. Additionally, data URIs are also handled just like normal web pages.

        if url.scheme == "http" || url.scheme == "https" || url.scheme == "data" || url.scheme == "blob" {
            if navigationAction.navigationType == .linkActivated {
                resetSpoofedUserAgentIfRequired(webView, newURL: url)
            } else if navigationAction.navigationType == .backForward {
                restoreSpoofedUserAgentIfRequired(webView, newRequest: navigationAction.request)
            }
            decisionHandler(WKNavigationActionPolicy.allow)
            return
        }

        // Default to calling openURL(). What this does depends on the iOS version. On iOS 8, it will just work without
        // prompting. On iOS9, depending on the scheme, iOS will prompt: "Firefox" wants to open "Twitter". It will ask
        // every time. There is no way around this prompt. (TODO Confirm this is true by adding them to the Info.plist)

        let openedURL = UIApplication.shared.openURL(url)
        if !openedURL {
            let alert = UIAlertController(title: Strings.UnableToOpenURLErrorTitle, message: Strings.UnableToOpenURLError, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: UIConstants.OKString, style: UIAlertActionStyle.default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
        decisionHandler(WKNavigationActionPolicy.cancel)
    }

    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        // If this is a certificate challenge, see if the certificate has previously been
        // accepted by the user.
        let origin = "\(challenge.protectionSpace.host):\(challenge.protectionSpace.port)"
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust,
           let cert = SecTrustGetCertificateAtIndex(trust, 0), profile.certStore.containsCertificate(cert, forOrigin: origin) {
            completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust: trust))
            return
        }

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPBasic ||
              challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodHTTPDigest ||
              challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodNTLM,
              let tab = tabManager[webView] else {
            completionHandler(URLSession.AuthChallengeDisposition.performDefaultHandling, nil)
            return
        }

        // If this is a request to our local web server, use our private credentials.
        if challenge.protectionSpace.host == "localhost" && challenge.protectionSpace.port == Int(WebServer.sharedInstance.server.port) {
            completionHandler(.useCredential, WebServer.sharedInstance.credentials)
            return
        }

        // The challenge may come from a background tab, so ensure it's the one visible.
        tabManager.selectTab(tab)

        let loginsHelper = tab.getHelper(name: LoginsHelper.name()) as? LoginsHelper
        Authenticator.handleAuthRequest(self, challenge: challenge, loginsHelper: loginsHelper).uponQueue(DispatchQueue.main) { res in
            if let credentials = res.successValue {
                completionHandler(.useCredential, credentials.credentials)
            } else {
                completionHandler(URLSession.AuthChallengeDisposition.rejectProtectionSpace, nil)
            }
        }
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        guard let tab = tabManager[webView] else { return }

        tab.url = webView.url
        self.scrollController.resetZoomState()

        if tabManager.selectedTab === tab {
            updateUIForReaderHomeStateForTab(tab)
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let tab: Tab! = tabManager[webView]
        navigateInTab(tab: tab, to: navigation)
    }
}
