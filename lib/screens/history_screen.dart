// lib/screens/history_screen.dart

import 'package:flutter/material.dart';
import '../services/history_service.dart';
import '../models/scan_result.dart';
import '../widgets/shared_widgets.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List<ScanResult> _all   = [];
  List<ScanResult> _shown = [];
  bool   _loading = true;
  String _filter  = 'all';

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final h = await HistoryService.getHistory();
    setState(() { _all = h; _loading = false; });
    _apply(_filter);
  }

  void _apply(String f) => setState(() {
    _filter = f;
    _shown  = switch (f) {
      'phishing'   => _all.where((r) => r.isPhishing).toList(),
      'safe'       => _all.where((r) => r.isSafe).toList(),
      'vt_flagged' => _all.where((r) => r.vtFlagged).toList(),
      _            => List.from(_all),
    };
  });

  Future<void> _clearAll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.card,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16)),
        title: const Text('Clear History?',
            style: TextStyle(color: AppColors.textPrimary)),
        content: const Text('All scan history will be permanently deleted.',
            style: TextStyle(color: AppColors.textSecondary)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel',
                style: TextStyle(color: AppColors.textSecondary))),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete',
                style: TextStyle(
                    color: AppColors.phishing,
                    fontWeight: FontWeight.bold))),
        ],
      ),
    );
    if (ok == true) { await HistoryService.clear(); _load(); }
  }

  @override
  Widget build(BuildContext context) {
    final ph       = _all.where((r) => r.isPhishing).length;
    final sf       = _all.length - ph;
    final vtFlagged = _all.where((r) => r.vtFlagged).length;

    return Scaffold(
      backgroundColor: AppColors.bg,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 20, 20, 0),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Scan History',
                          style: TextStyle(
                              color: AppColors.textPrimary,
                              fontSize: 22,
                              fontWeight: FontWeight.bold)),
                      Text('All previous scans with VT results',
                          style: TextStyle(
                              color: AppColors.textSecondary, fontSize: 13)),
                    ],
                  ),
                  if (_all.isNotEmpty)
                    Row(children: [
                      IconButton(
                        icon: const Icon(Icons.refresh,
                            color: AppColors.textSecondary),
                        onPressed: _load,
                        tooltip: 'Refresh',
                      ),
                      IconButton(
                        icon: const Icon(Icons.delete_outline,
                            color: AppColors.textSecondary),
                        onPressed: _clearAll,
                        tooltip: 'Clear all',
                      ),
                    ]),
                ],
              ),
            ),

            // Stats row
            if (_all.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 14, 20, 0),
                child: Row(children: [
                  _Stat('${_all.length}', 'Total', AppColors.accent),
                  const SizedBox(width: 7),
                  _Stat('$ph', 'Phishing', AppColors.phishing),
                  const SizedBox(width: 7),
                  _Stat('$sf', 'Safe', AppColors.safe),
                  const SizedBox(width: 7),
                  _Stat('$vtFlagged', 'VT Flagged', AppColors.vtColor),
                ]),
              ),

            // Filter tabs
            if (_all.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 0),
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(children: [
                    _Tab('All', 'all', _filter, _apply, AppColors.accent),
                    const SizedBox(width: 7),
                    _Tab('Phishing', 'phishing', _filter, _apply,
                        AppColors.phishing),
                    const SizedBox(width: 7),
                    _Tab('Safe', 'safe', _filter, _apply, AppColors.safe),
                    const SizedBox(width: 7),
                    _Tab('VT Flagged', 'vt_flagged', _filter, _apply,
                        AppColors.vtColor),
                  ]),
                ),
              ),

            const SizedBox(height: 12),

            Expanded(
              child: _loading
                  ? const Center(
                      child: CircularProgressIndicator(
                          color: AppColors.accent))
                  : _shown.isEmpty
                      ? Center(
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const Icon(Icons.history,
                                  color: AppColors.textSecondary, size: 56),
                              const SizedBox(height: 14),
                              Text(
                                _filter == 'all'
                                    ? 'No scans yet'
                                    : 'No $_filter scans found',
                                style: const TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 15,
                                    fontWeight: FontWeight.w500)),
                              const SizedBox(height: 6),
                              const Text(
                                'Start scanning URLs to see results here',
                                style: TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 13)),
                            ],
                          ),
                        )
                      : RefreshIndicator(
                          onRefresh: _load,
                          color: AppColors.accent,
                          child: ListView.builder(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 20),
                            itemCount: _shown.length,
                            itemBuilder: (_, i) =>
                                ScanCard(r: _shown[i]),
                          ),
                        ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  final String val, label;
  final Color color;
  const _Stat(this.val, this.label, this.color);
  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: color.withOpacity(0.25)),
          ),
          child: Column(children: [
            Text(val,
                style: TextStyle(
                    color: color,
                    fontSize: 18,
                    fontWeight: FontWeight.bold)),
            Text(label,
                style: const TextStyle(
                    color: AppColors.textSecondary, fontSize: 10),
                textAlign: TextAlign.center),
          ]),
        ),
      );
}

class _Tab extends StatelessWidget {
  final String label, value, current;
  final void Function(String) onTap;
  final Color color;
  const _Tab(this.label, this.value, this.current, this.onTap, this.color);
  @override
  Widget build(BuildContext context) {
    final active = current == value;
    return GestureDetector(
      onTap: () => onTap(value),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        decoration: BoxDecoration(
          color: active ? color.withOpacity(0.15) : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: active
                ? color.withOpacity(0.5)
                : AppColors.textSecondary.withOpacity(0.2),
          ),
        ),
        child: Text(label,
            style: TextStyle(
                color: active ? color : AppColors.textSecondary,
                fontSize: 13,
                fontWeight:
                    active ? FontWeight.w600 : FontWeight.normal)),
      ),
    );
  }
}
