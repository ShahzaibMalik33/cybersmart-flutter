// lib/models/file_scan_result.dart

class FileScanResult {
  final String fileName;
  final String filePath;
  final String fileType;   // 'pdf', 'word', 'exe', 'other'
  final int    fileSize;   // bytes
  final String sha256;
  final DateTime scannedAt;

  // VirusTotal results
  final int?    vtMalicious;
  final int?    vtSuspicious;
  final int?    vtClean;
  final int?    vtUndetected;
  final int?    vtTotal;
  final String? vtPermalink;
  final String? vtStatus;   // 'pending' | 'uploading' | 'done' | 'error'
  final String? vtError;

  // Overall verdict
  final String verdict;   // 'Clean' | 'Malicious' | 'Suspicious' | 'Unknown'
  final String threatName; // e.g. 'Trojan.GenericKD' or 'Clean'

  const FileScanResult({
    required this.fileName,
    required this.filePath,
    required this.fileType,
    required this.fileSize,
    required this.sha256,
    required this.scannedAt,
    this.vtMalicious,
    this.vtSuspicious,
    this.vtClean,
    this.vtUndetected,
    this.vtTotal,
    this.vtPermalink,
    this.vtStatus,
    this.vtError,
    this.verdict   = 'Unknown',
    this.threatName = '',
  });

  bool get isMalicious   => verdict == 'Malicious';
  bool get isSuspicious  => verdict == 'Suspicious';
  bool get isClean       => verdict == 'Clean';
  bool get isFlagged     => isMalicious || isSuspicious;
  bool get hasVtData     => vtStatus == 'done' && vtTotal != null && vtTotal! > 0;

  String get fileSizeFormatted {
    if (fileSize < 1024) return '$fileSize B';
    if (fileSize < 1024 * 1024) return '${(fileSize / 1024).toStringAsFixed(1)} KB';
    return '${(fileSize / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  String get fileTypeLabel {
    switch (fileType) {
      case 'pdf':  return 'PDF Document';
      case 'word': return 'Word Document';
      case 'exe':  return 'Executable File';
      case 'apk':  return 'Android APK';
      case 'zip':  return 'ZIP Archive';
      default:     return 'File';
    }
  }

  Map<String, dynamic> toJson() => {
    'fileName':     fileName,
    'filePath':     filePath,
    'fileType':     fileType,
    'fileSize':     fileSize,
    'sha256':       sha256,
    'scannedAt':    scannedAt.toIso8601String(),
    'vtMalicious':  vtMalicious,
    'vtSuspicious': vtSuspicious,
    'vtClean':      vtClean,
    'vtUndetected': vtUndetected,
    'vtTotal':      vtTotal,
    'vtPermalink':  vtPermalink,
    'vtStatus':     vtStatus,
    'vtError':      vtError,
    'verdict':      verdict,
    'threatName':   threatName,
  };

  factory FileScanResult.fromJson(Map<String, dynamic> j) => FileScanResult(
    fileName:     j['fileName']     ?? '',
    filePath:     j['filePath']     ?? '',
    fileType:     j['fileType']     ?? 'other',
    fileSize:     j['fileSize']     ?? 0,
    sha256:       j['sha256']       ?? '',
    scannedAt:    DateTime.parse(
        j['scannedAt'] ?? DateTime.now().toIso8601String()),
    vtMalicious:  j['vtMalicious'],
    vtSuspicious: j['vtSuspicious'],
    vtClean:      j['vtClean'],
    vtUndetected: j['vtUndetected'],
    vtTotal:      j['vtTotal'],
    vtPermalink:  j['vtPermalink'],
    vtStatus:     j['vtStatus'],
    vtError:      j['vtError'],
    verdict:      j['verdict']      ?? 'Unknown',
    threatName:   j['threatName']   ?? '',
  );

  FileScanResult copyWith({
    int?    vtMalicious,
    int?    vtSuspicious,
    int?    vtClean,
    int?    vtUndetected,
    int?    vtTotal,
    String? vtPermalink,
    String? vtStatus,
    String? vtError,
    String? verdict,
    String? threatName,
  }) => FileScanResult(
    fileName:     fileName,
    filePath:     filePath,
    fileType:     fileType,
    fileSize:     fileSize,
    sha256:       sha256,
    scannedAt:    scannedAt,
    vtMalicious:  vtMalicious  ?? this.vtMalicious,
    vtSuspicious: vtSuspicious ?? this.vtSuspicious,
    vtClean:      vtClean      ?? this.vtClean,
    vtUndetected: vtUndetected ?? this.vtUndetected,
    vtTotal:      vtTotal      ?? this.vtTotal,
    vtPermalink:  vtPermalink  ?? this.vtPermalink,
    vtStatus:     vtStatus     ?? this.vtStatus,
    vtError:      vtError      ?? this.vtError,
    verdict:      verdict      ?? this.verdict,
    threatName:   threatName   ?? this.threatName,
  );
}
