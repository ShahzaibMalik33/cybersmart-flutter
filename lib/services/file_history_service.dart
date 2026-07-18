// lib/services/file_history_service.dart

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/file_scan_result.dart';

class FileHistoryService {
  static const _key = 'file_scan_history_v1';

  static Future<List<FileScanResult>> getHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    final list  = <FileScanResult>[];
    for (final s in raw) {
      try { list.add(FileScanResult.fromJson(json.decode(s))); } catch (_) {}
    }
    return list.reversed.toList(); // newest first
  }

  static Future<void> add(FileScanResult r) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    raw.add(json.encode(r.toJson()));
    if (raw.length > 100) raw.removeRange(0, raw.length - 100);
    await prefs.setStringList(_key, raw);
  }

  static Future<void> update(FileScanResult updated) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    for (int i = 0; i < raw.length; i++) {
      try {
        final r = FileScanResult.fromJson(json.decode(raw[i]));
        if (r.sha256 == updated.sha256 &&
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
