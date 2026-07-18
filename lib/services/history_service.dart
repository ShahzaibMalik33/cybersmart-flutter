// lib/services/history_service.dart

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/scan_result.dart';

class HistoryService {
  static const _key = 'scan_history_v2';

  static Future<List<ScanResult>> getHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    final list  = <ScanResult>[];
    for (final s in raw) {
      try { list.add(ScanResult.fromJson(json.decode(s))); } catch (_) {}
    }
    return list.reversed.toList(); // newest first
  }

  static Future<void> add(ScanResult r) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    raw.add(json.encode(r.toJson()));
    // keep max 200 entries
    if (raw.length > 200) raw.removeRange(0, raw.length - 200);
    await prefs.setStringList(_key, raw);
  }

  /// Update an existing entry (matched by URL + scannedAt)
  static Future<void> update(ScanResult updated) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    for (int i = 0; i < raw.length; i++) {
      try {
        final r = ScanResult.fromJson(json.decode(raw[i]));
        if (r.url == updated.url &&
            r.scannedAt.isAtSameMomentAs(updated.scannedAt)) {
          raw[i] = json.encode(updated.toJson());
          break;
        }
      } catch (_) {}
    }
    await prefs.setStringList(_key, raw);
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}
