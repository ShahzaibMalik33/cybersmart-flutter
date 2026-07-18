// lib/services/phishing_detector.dart

import 'package:tflite_flutter/tflite_flutter.dart';

class PhishingDetector {
  static Interpreter? _interpreter;
  static bool _ready = false;

  static bool get isReady => _ready;

  static Future<void> init() async {
    try {
      final opts = InterpreterOptions()..threads = 2;
      _interpreter = await Interpreter.fromAsset(
        'assets/model.tflite',
        options: opts,
      );
      _ready = true;
    } catch (e) {
      _ready = false;
    }
  }

  // ── URL validator ─────────────────────────────────────────────
  /// Returns true only if input looks like a real URL or domain
  static bool isValidUrl(String input) {
    final t = input.trim().toLowerCase();
    if (t.isEmpty) return false;

    // Must start with http/https/www OR be a domain-like string
    final urlPattern = RegExp(
      r'^(https?://|www\.)[^\s]{3,}|'          // http/https/www. prefix
      r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.'  // domain-like: example.
      r'(com|net|org|io|gov|edu|co|uk|pk|in|'
      r'de|fr|ru|cn|jp|br|au|ca|ml|cf|tk|ga|'
      r'gq|xyz|top|pw|info|biz|live|online|'
      r'site|web|app|dev|tech|store|shop|'
      r'click|link|me|us|eu)',
      caseSensitive: false,
    );
    if (!urlPattern.hasMatch(t)) return false;

    // Reject if it has spaces (plain text, not URL)
    if (input.trim().contains(' ')) return false;

    // Must have at least one dot
    if (!input.contains('.')) return false;

    return true;
  }

  // ── Public scan entry-point ───────────────────────────────────
  static Map<String, dynamic> scan(String rawUrl) {
    final url      = rawUrl.trim();
    final features = _extractFeatures(url);

    double prob;
    String method;

    if (_ready && _interpreter != null) {
      final modelProb = _runModel(features);
      // Blend model output with heuristic for more balanced results
      final heurProb  = _heuristicScore(url);
      // Weight: 70% model, 30% heuristic
      prob   = (modelProb * 0.70) + (heurProb * 0.30);
      method = 'AI Model (On-Device)';
    } else {
      prob   = _heuristicScore(url);
      method = 'Heuristic Engine';
    }

    // Clamp to realistic range: never show exactly 0% or 100%
    // Min safe = 5%, max safe = 88%, min phish = 55%, max phish = 92%
    if (prob < 0.50) {
      prob = prob.clamp(0.05, 0.48); // safe range: 5% – 48%
    } else {
      prob = prob.clamp(0.55, 0.92); // phishing range: 55% – 92%
    }

    final isPhishing = prob > 0.50;
    final pct        = prob * 100;

    String confidence;
    String riskLevel;

    if (pct >= 80) {
      confidence = 'Very High';
      riskLevel  = isPhishing ? 'Critical Risk' : 'Very Safe';
    } else if (pct >= 65) {
      confidence = 'High';
      riskLevel  = isPhishing ? 'High Risk' : 'Safe';
    } else if (pct >= 50) {
      confidence = 'Medium';
      riskLevel  = isPhishing ? 'Medium Risk' : 'Likely Safe';
    } else {
      confidence = 'Low';
      riskLevel  = isPhishing ? 'Suspicious' : 'Likely Safe';
    }

    return {
      'url':         url,
      'label':       isPhishing ? 'Phishing' : 'Safe',
      'probability': prob,
      'confidence':  confidence,
      'risk_level':  riskLevel,
      'method':      method,
    };
  }

  // ── TFLite inference ──────────────────────────────────────────
  static double _runModel(List<double> features) {
    try {
      final input  = [features];
      final output = List.generate(1, (_) => List<double>.filled(2, 0.0));
      _interpreter!.run(input, output);
      return output[0][1].clamp(0.0, 1.0);
    } catch (_) {
      return 0.3; // neutral fallback, not 0
    }
  }

  // ── Improved heuristic score ──────────────────────────────────
  static double _heuristicScore(String rawUrl) {
    final url = rawUrl.trim().toLowerCase();
    double score = 0.15; // baseline — start at 15% not 0%

    // ── Strong phishing signals (high weight) ──
    // IP address as host
    if (RegExp(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').hasMatch(url)) {
      score += 0.35;
    }

    // No HTTPS
    if (url.startsWith('http://') && !url.startsWith('https://')) {
      score += 0.12;
    }

    // @ symbol in URL (classic phishing trick)
    if (url.contains('@')) score += 0.20;

    // Suspicious TLDs commonly used by phishers
    final badTlds = ['.ml', '.cf', '.tk', '.ga', '.gq', '.pw', '.xyz',
                     '.top', '.click', '.live', '.online'];
    for (final t in badTlds) {
      if (url.contains(t)) { score += 0.18; break; }
    }

    // URL shorteners (hide real destination)
    final shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly',
                        't.co', 'is.gd', 'cutt.ly', 'rb.gy'];
    if (shorteners.any((s) => url.contains(s))) score += 0.15;

    // ── Brand impersonation (typosquatting) — KEY FIX ──
    // Check for brand names with small misspellings
    final brands = {
      'facebook':   ['fakebook', 'faceb00k', 'facebok', 'face-book'],
      'google':     ['g00gle', 'gooogle', 'googgle'],
      'paypal':     ['paypa1', 'paypa-l', 'paypai'],
      'amazon':     ['amaz0n', 'arnazon', 'amzon'],
      'netflix':    ['netf1ix', 'netfl1x'],
      'apple':      ['app1e', 'appie'],
      'microsoft':  ['micros0ft', 'microsofe'],
      'whatsapp':   ['whatssapp', 'whatsap'],
      'instagram':  ['instagrarr', 'instagramm'],
      'youtube':    ['y0utube', 'yout-ube'],
      'twitter':    ['tw1tter', 'twltter'],
      'bank':       ['bancorp', 'b4nk'],
      'hbl':        ['hb1', 'hb-l'],
    };

    for (final entry in brands.entries) {
      final brand    = entry.key;
      final variants = entry.value;
      for (final v in variants) {
        if (url.contains(v)) { score += 0.35; break; }
      }
      // Real brand name in URL but domain isn't the real one
      if (url.contains(brand) &&
          !url.contains('$brand.com') &&
          !url.contains('$brand.org') &&
          !url.contains('$brand.net')) {
        score += 0.10;
      }
    }

    // ── Phishing keywords ──
    final highRiskWords = ['login', 'signin', 'verify', 'password',
        'account', 'credential', 'banking', 'confirm', 'suspend',
        'validate', 'update-account', 'secure-login'];
    int keywordCount = 0;
    for (final w in highRiskWords) {
      if (url.contains(w)) keywordCount++;
    }
    score += (keywordCount * 0.06).clamp(0, 0.18);

    final medRiskWords = ['free', 'prize', 'winner', 'claim',
        'urgent', 'limited', 'offer', 'click-here', 'track'];
    for (final w in medRiskWords) {
      if (url.contains(w)) score += 0.04;
    }

    // ── URL structure signals ──
    // Excessive dashes in domain
    final host = _extractHost(url);
    final dashCount = '-'.allMatches(host).length;
    if (dashCount >= 3) score += 0.10;
    if (dashCount >= 5) score += 0.10;

    // Too many subdomains
    final dotCount = '.'.allMatches(host).length;
    if (dotCount >= 4) score += 0.12;

    // Very long URL
    if (url.length > 100) score += 0.08;
    if (url.length > 150) score += 0.08;

    // Encoded characters (obfuscation)
    if (url.contains('%')) score += 0.06;

    // Double slash redirect
    if (url.replaceFirst('//', '').contains('//')) score += 0.08;

    // ── Safety signals (reduce score) ──
    final trustedDomains = [
      'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
      'twitter.com', 'linkedin.com', 'microsoft.com', 'apple.com',
      'amazon.com', 'wikipedia.org', 'github.com', 'stackoverflow.com',
      'paypal.com', 'netflix.com', 'spotify.com', 'reddit.com',
    ];
    for (final d in trustedDomains) {
      if (url.contains(d)) {
        score -= 0.30;
        break;
      }
    }

    // HTTPS is a positive signal
    if (url.startsWith('https://')) score -= 0.05;

    // Simple, short domain with no tricks
    if (host.isNotEmpty && !host.contains('-') && dotCount <= 1) {
      score -= 0.05;
    }

    return score.clamp(0.05, 0.95);
  }

  static String _extractHost(String url) {
    try {
      final u   = url.startsWith('http') ? url : 'http://$url';
      final uri = Uri.tryParse(u);
      return uri?.host ?? '';
    } catch (_) {
      return '';
    }
  }

  // ── 56 Feature extraction (for TFLite model) ─────────────────
  static List<double> _extractFeatures(String url) {
    final u      = url.toLowerCase();
    final uri    = Uri.tryParse(url.startsWith('http') ? url : 'http://$url');
    final host   = uri?.host ?? '';
    final path   = uri?.path ?? '';
    final query  = uri?.query ?? '';
    final len    = url.length;

    int cnt(String s, String ch) => ch.allMatches(s).length;

    final hasIp = RegExp(r'\b\d{1,3}(\.\d{1,3}){3}\b').hasMatch(host);
    final subCount = host.split('.').length - 2;

    double f0  = hasIp ? 1 : -1;
    double f1  = len < 54 ? 1 : len <= 75 ? 0 : -1;
    final shorteners = ['bit.ly','tinyurl','goo.gl','ow.ly','t.co','is.gd','cutt.ly'];
    double f2  = shorteners.any((s) => u.contains(s)) ? -1 : 1;
    double f3  = u.contains('@') ? -1 : 1;
    double f4  = path.contains('//') ? -1 : 1;
    double f5  = host.contains('-') ? -1 : 1;
    double f6  = subCount <= 1 ? 1 : subCount == 2 ? 0 : -1;
    double f7  = url.startsWith('https') ? 1 : -1;
    double f8  = 0;
    double f9  = 0;
    double f10 = (uri?.port != null && uri!.port != 80 &&
                  uri.port != 443 && uri.port > 0) ? -1 : 1;
    double f11 = host.contains('https') ? -1 : 1;
    double f12 = 0;
    double f13 = 0;
    double f14 = 0;
    double f15 = 0;
    double f16 = u.contains('mailto:') ? -1 : 1;
    double f17 = hasIp ? -1 : 1;
    final rDir = '//'.allMatches(url.length > 8 ? url.substring(8) : url).length;
    double f18 = rDir < 2 ? 1 : rDir <= 4 ? 0 : -1;
    double f19 = 0;
    double f20 = 0;
    double f21 = 0;
    double f22 = 0;
    double f23 = 0;
    double f24 = hasIp ? -1 : 1;
    double f25 = 0;
    double f26 = 0;
    double f27 = 0;
    double f28 = 0;
    double f29 = 0;
    double f30 = len > 100 ? -1 : 1;
    double f31 = cnt(url, '.') > 4 ? -1 : 1;
    double f32 = cnt(url, '-') > 4 ? -1 : 1;
    double f33 = cnt(url, '_') > 3 ? -1 : 1;
    double f34 = cnt(url, '/') > 6 ? -1 : 1;
    double f35 = cnt(url, '?') > 1 ? -1 : 1;
    double f36 = cnt(url, '=') > 3 ? -1 : 1;
    double f37 = cnt(url, '@') > 0 ? -1 : 1;
    double f38 = cnt(url, '!') > 0 ? -1 : 1;
    double f39 = cnt(url, ' ') > 0 ? -1 : 1;
    final suspWords = ['login','signin','verify','update','secure','account',
      'banking','paypal','ebay','amazon','password','confirm','suspend'];
    double f40 = suspWords.any((w) => u.contains(w)) ? -1 : 1;
    final suspTlds = ['.ml','.cf','.tk','.ga','.gq','.xyz','.top','.pw'];
    double f41 = suspTlds.any((t) => u.contains(t)) ? -1 : 1;
    double f42 = host.length > 30 ? -1 : 1;
    double f43 = subCount > 3 ? -1 : 1;
    double f44 = query.length > 50 ? -1 : 1;
    double f45 = path.length > 60 ? -1 : 1;
    double f46 = u.contains('%') ? -1 : 1;
    double f47 = u.contains('redirect') || u.contains('redir') ? -1 : 1;
    double f48 = u.contains('click') || u.contains('track') ? -1 : 1;
    double f49 = u.contains('free') || u.contains('prize') ? -1 : 1;
    double f50 = 1;
    double f51 = cnt(host, '-') > 2 ? -1 : 1;
    double f52 = host.contains('secure') || host.contains('safe') ? -1 : 1;
    double f53 = host.contains('bank') || host.contains('pay') ? -0.5 : 1;
    double f54 = url.startsWith('http://') ? -1 : 1;
    double f55 = u.contains('%20') ? -1 : 1;

    return [
      f0, f1, f2, f3, f4, f5, f6, f7, f8, f9,
      f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,
      f20,f21,f22,f23,f24,f25,f26,f27,f28,f29,
      f30,f31,f32,f33,f34,f35,f36,f37,f38,f39,
      f40,f41,f42,f43,f44,f45,f46,f47,f48,f49,
      f50,f51,f52,f53,f54,f55,
    ];
  }
}
