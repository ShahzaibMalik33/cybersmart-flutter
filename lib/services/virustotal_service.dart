// lib/services/virustotal_service.dart

import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

class VirusTotalService {
  static const String _apiKey =
      '3c9745096390778e596508af9e7c7aaf9a119095ec85ca93c8ee5f9b4b80a2d0';
  static const String _base = 'https://www.virustotal.com/api/v3';

  // Common headers for every request
  static Map<String, String> get _headers => {
    'x-apikey': _apiKey,
    'Accept':   'application/json',
  };

  // ── URL Scan ────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> scanUrl(String url) async {
    try {
      // Step 1: Submit URL
      final submitResp = await http.post(
        Uri.parse('$_base/urls'),
        headers: {
          ..._headers,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: {'url': url},
      ).timeout(const Duration(seconds: 20));

      if (submitResp.statusCode == 429) {
        return _err('VT rate limit reached. Please wait 1 minute and retry.');
      }
      if (submitResp.statusCode == 401) {
        return _err('VT API key invalid or expired.');
      }
      if (submitResp.statusCode != 200) {
        return _err('VT error ${submitResp.statusCode}. Try again.');
      }

      final submitJson = json.decode(submitResp.body);
      final analysisId = submitJson['data']?['id'] as String?;
      if (analysisId == null || analysisId.isEmpty) {
        return _err('No analysis ID returned by VirusTotal.');
      }

      // Step 2: Poll analysis (5 attempts, growing delay)
      for (int i = 0; i < 5; i++) {
        await Future.delayed(Duration(seconds: i == 0 ? 3 : 4));

        final pollResp = await http.get(
          Uri.parse('$_base/analyses/$analysisId'),
          headers: _headers,
        ).timeout(const Duration(seconds: 15));

        if (pollResp.statusCode != 200) continue;

        final pollJson = json.decode(pollResp.body);
        final status   = pollJson['data']?['attributes']?['status'] as String?;

        if (status == 'completed') {
          return _parseStats(
            pollJson['data']['attributes']['stats'] as Map<String, dynamic>,
            'url',
            url,
          );
        }
      }

      return _err('VT analysis is queued. Please tap Retry in 30 seconds.');
    } on SocketException {
      return _err('No internet connection. Connect to Wi-Fi or mobile data.');
    } on HttpException catch (e) {
      return _err('HTTP error: ${_trim(e)}');
    } on FormatException {
      return _err('VT returned unexpected data. Try again.');
    } catch (e) {
      final msg = e.toString();
      if (msg.contains('TimeoutException') || msg.contains('timeout')) {
        return _err('VT request timed out. Check your connection speed.');
      }
      if (msg.contains('HandshakeException') || msg.contains('certificate')) {
        return _err('SSL error. Make sure date/time on your phone is correct.');
      }
      return _err('Unexpected error: ${_trim(e)}');
    }
  }

  // ── File Scan ───────────────────────────────────────────────────
  static Future<Map<String, dynamic>> scanFile(
    String filePath, {
    void Function(String stage)? onStage,
  }) async {
    try {
      final file = File(filePath);
      if (!await file.exists()) {
        return _err('File not found: $filePath');
      }

      final bytes      = await file.readAsBytes();
      final sha256Hash = sha256.convert(bytes).toString();
      final sizeMb     = bytes.length / (1024 * 1024);

      if (bytes.length > 32 * 1024 * 1024) {
        return _err(
            'File is ${sizeMb.toStringAsFixed(1)} MB. '
            'VirusTotal free tier supports up to 32 MB.');
      }

      onStage?.call('checking');

      // Check if hash already known
      final hashResp = await http.get(
        Uri.parse('$_base/files/$sha256Hash'),
        headers: _headers,
      ).timeout(const Duration(seconds: 15));

      if (hashResp.statusCode == 200) {
        onStage?.call('parsing');
        return _parseFileReport(hashResp.body, sha256Hash);
      }

      // Upload file
      onStage?.call('uploading');
      final fileName = filePath.split(Platform.pathSeparator).last;
      final request  = http.MultipartRequest('POST', Uri.parse('$_base/files'));
      request.headers.addAll(_headers);
      request.files.add(
          http.MultipartFile.fromBytes('file', bytes, filename: fileName));

      final streamed  = await request.send().timeout(const Duration(seconds: 120));
      final uploadBody = await streamed.stream.bytesToString();

      if (streamed.statusCode == 429) {
        return _err('VT rate limit reached. Wait 1 minute and retry.');
      }
      if (streamed.statusCode != 200) {
        return _err('Upload failed (HTTP ${streamed.statusCode}).');
      }

      final uploadJson = json.decode(uploadBody);
      final analysisId = uploadJson['data']?['id'] as String?;
      if (analysisId == null) {
        return _err('Upload succeeded but no analysis ID returned.');
      }

      // Poll for file analysis
      onStage?.call('scanning');
      for (int i = 0; i < 8; i++) {
        await Future.delayed(Duration(seconds: i < 3 ? 5 : 8));

        final pollResp = await http.get(
          Uri.parse('$_base/analyses/$analysisId'),
          headers: _headers,
        ).timeout(const Duration(seconds: 15));

        if (pollResp.statusCode != 200) continue;

        final pollJson = json.decode(pollResp.body);
        final status   = pollJson['data']?['attributes']?['status'] as String?;

        if (status == 'completed') {
          onStage?.call('parsing');
          await Future.delayed(const Duration(seconds: 2));

          final fullResp = await http.get(
            Uri.parse('$_base/files/$sha256Hash'),
            headers: _headers,
          ).timeout(const Duration(seconds: 15));

          if (fullResp.statusCode == 200) {
            return _parseFileReport(fullResp.body, sha256Hash);
          }

          // Fallback: parse from analysis stats
          final stats     = pollJson['data']['attributes']['stats'] as Map<String, dynamic>;
          return _parseStats(stats, 'file', sha256Hash);
        }
      }

      return _err(
          'Scan still running. Visit virustotal.com/gui/file/$sha256Hash to check.');
    } on SocketException {
      return _err('No internet connection.');
    } catch (e) {
      return _err('File scan error: ${_trim(e)}');
    }
  }

  // ── Parse stats from analysis ───────────────────────────────────
  static Map<String, dynamic> _parseStats(
    Map<String, dynamic> stats,
    String type,
    String identifier,
  ) {
    final malicious  = (stats['malicious']  ?? 0) as int;
    final suspicious = (stats['suspicious'] ?? 0) as int;
    final harmless   = (stats['harmless']   ?? 0) as int;
    final undetected = (stats['undetected'] ?? 0) as int;
    final total      = malicious + suspicious + harmless + undetected;

    final verdict = malicious > 0
        ? 'Malicious'
        : suspicious > 0 ? 'Suspicious' : 'Clean';

    String permalink;
    if (type == 'url') {
      final urlId = base64Url
          .encode(utf8.encode(identifier))
          .replaceAll('=', '');
      permalink = 'https://www.virustotal.com/gui/url/$urlId';
    } else {
      permalink = 'https://www.virustotal.com/gui/file/$identifier';
    }

    return {
      'status':     'done',
      'malicious':  malicious,
      'suspicious': suspicious,
      'clean':      harmless + (type == 'url' ? undetected : 0),
      'undetected': undetected,
      'total':      total,
      'verdict':    verdict,
      'threatName': '',
      'permalink':  permalink,
    };
  }

  // ── Parse full file report ──────────────────────────────────────
  static Map<String, dynamic> _parseFileReport(
      String body, String sha256Hash) {
    try {
      final data  = json.decode(body);
      final attrs = data['data']['attributes'] as Map<String, dynamic>;
      final stats =
          attrs['last_analysis_stats'] as Map<String, dynamic>? ?? {};

      final malicious  = (stats['malicious']  ?? 0) as int;
      final suspicious = (stats['suspicious'] ?? 0) as int;
      final harmless   = (stats['harmless']   ?? 0) as int;
      final undetected = (stats['undetected'] ?? 0) as int;
      final total      = malicious + suspicious + harmless + undetected;

      String threatName = '';
      final results =
          attrs['last_analysis_results'] as Map<String, dynamic>?;
      if (results != null) {
        final names = <String>[];
        for (final v in results.values) {
          final cat    = v['category'] as String? ?? '';
          final result = v['result']   as String? ?? '';
          if ((cat == 'malicious' || cat == 'suspicious') &&
              result.isNotEmpty) {
            names.add(result);
          }
        }
        if (names.isNotEmpty) {
          names.sort((a, b) => a.length.compareTo(b.length));
          threatName = names.first;
        }
      }

      return {
        'status':     'done',
        'sha256':     sha256Hash,
        'malicious':  malicious,
        'suspicious': suspicious,
        'clean':      harmless,
        'undetected': undetected,
        'total':      total,
        'verdict':    malicious > 0 ? 'Malicious' : suspicious > 0 ? 'Suspicious' : 'Clean',
        'threatName': threatName,
        'permalink':  'https://www.virustotal.com/gui/file/$sha256Hash',
      };
    } catch (e) {
      return _err('Failed to parse VT file report: ${_trim(e)}');
    }
  }

  static String _trim(Object e) {
    final s = e.toString();
    return s.length > 90 ? '${s.substring(0, 90)}...' : s;
  }

  static Map<String, dynamic> _err(String msg) => {
    'status':     'error',
    'error':      msg,
    'malicious':  0,
    'suspicious': 0,
    'clean':      0,
    'undetected': 0,
    'total':      0,
    'verdict':    'Unknown',
    'threatName': '',
  };
}
