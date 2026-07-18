
class ScanResult {
  final String url;
  final String label;
  final double probability;
  final String confidence;
  final String riskLevel;
  final String method;
  final DateTime scannedAt;
  final String scanType;

  // VirusTotal fields
  final int? vtMalicious;
  final int? vtSuspicious;
  final int? vtClean;
  final int? vtTotal;
  final String? vtPermalink;
  final String? vtStatus; // 'pending', 'done', 'error', 'not_checked'

  const ScanResult({
    required this.url,
    required this.label,
    required this.probability,
    required this.confidence,
    required this.riskLevel,
    required this.method,
    required this.scannedAt,
    this.scanType = 'url',
    this.vtMalicious,
    this.vtSuspicious,
    this.vtClean,
    this.vtTotal,
    this.vtPermalink,
    this.vtStatus,
  });

  bool get isPhishing => label == 'Phishing';
  bool get isSafe => !isPhishing;

  bool get hasVtData =>
      vtStatus == 'done' && vtTotal != null && vtTotal! > 0;

  bool get vtFlagged => (vtMalicious ?? 0) > 0 || (vtSuspicious ?? 0) > 0;

  Map<String, dynamic> toJson() => {
        'url': url,
        'label': label,
        'probability': probability,
        'confidence': confidence,
        'riskLevel': riskLevel,
        'method': method,
        'scannedAt': scannedAt.toIso8601String(),
        'scanType': scanType,
        'vtMalicious': vtMalicious,
        'vtSuspicious': vtSuspicious,
        'vtClean': vtClean,
        'vtTotal': vtTotal,
        'vtPermalink': vtPermalink,
        'vtStatus': vtStatus,
      };

  factory ScanResult.fromJson(Map<String, dynamic> j) => ScanResult(
        url: j['url'] ?? '',
        label: j['label'] ?? 'Unknown',
        probability: (j['probability'] ?? 0.0).toDouble(),
        confidence: j['confidence'] ?? 'Low',
        riskLevel: j['riskLevel'] ?? 'Unknown',
        method: j['method'] ?? 'Unknown',
        scannedAt: DateTime.parse(
            j['scannedAt'] ?? DateTime.now().toIso8601String()),
        scanType: j['scanType'] ?? 'url',
        vtMalicious: j['vtMalicious'],
        vtSuspicious: j['vtSuspicious'],
        vtClean: j['vtClean'],
        vtTotal: j['vtTotal'],
        vtPermalink: j['vtPermalink'],
        vtStatus: j['vtStatus'],
      );

  ScanResult copyWith({
    int? vtMalicious,
    int? vtSuspicious,
    int? vtClean,
    int? vtTotal,
    String? vtPermalink,
    String? vtStatus,
  }) =>
      ScanResult(
        url: url,
        label: label,
        probability: probability,
        confidence: confidence,
        riskLevel: riskLevel,
        method: method,
        scannedAt: scannedAt,
        scanType: scanType,
        vtMalicious: vtMalicious ?? this.vtMalicious,
        vtSuspicious: vtSuspicious ?? this.vtSuspicious,
        vtClean: vtClean ?? this.vtClean,
        vtTotal: vtTotal ?? this.vtTotal,
        vtPermalink: vtPermalink ?? this.vtPermalink,
        vtStatus: vtStatus ?? this.vtStatus,
      );
}
