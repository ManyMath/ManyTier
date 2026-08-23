import 'dart:typed_data';

class EmbeddedNodeException implements Exception {
  const EmbeddedNodeException(this.message);

  final String message;

  @override
  String toString() => message;
}

enum EmbeddedNodeActionKind {
  unknown(0),
  sendTo(1),
  whoisNeeded(2),
  frameReceived(3),
  localReply(4),
  networkConfigured(5),
  networkConfigRequested(6),
  userMessageReceived(7),
  remoteTraceReceived(8),
  pathNegotiationReceived(9),
  destinationUnknown(10);

  const EmbeddedNodeActionKind(this.ffiCode);

  final int ffiCode;

  static EmbeddedNodeActionKind fromFfiCode(int code) {
    for (final kind in values) {
      if (kind.ffiCode == code) return kind;
    }
    return unknown;
  }
}

class EmbeddedSocketAddress {
  EmbeddedSocketAddress({
    required this.family,
    required List<int> address,
    required this.port,
  }) : address = List<int>.unmodifiable(address) {
    if (family != 4 && family != 6) {
      throw ArgumentError.value(family, 'family', 'must be 4 or 6');
    }
    if (address.length != 16) {
      throw ArgumentError.value(address.length, 'address.length', 'must be 16');
    }
    if (port < 0 || port > 65535) {
      throw RangeError.range(port, 0, 65535, 'port');
    }
    for (final byte in address) {
      if (byte < 0 || byte > 255) {
        throw RangeError.range(byte, 0, 255, 'address byte');
      }
    }
  }

  factory EmbeddedSocketAddress.ipv4(int a, int b, int c, int d, int port) {
    return EmbeddedSocketAddress(
      family: 4,
      address: <int>[a, b, c, d, ...List<int>.filled(12, 0)],
      port: port,
    );
  }

  factory EmbeddedSocketAddress.ipv6(List<int> address, int port) {
    if (address.length != 16) {
      throw ArgumentError.value(address.length, 'address.length', 'must be 16');
    }
    return EmbeddedSocketAddress(
      family: 6,
      address: List<int>.unmodifiable(address),
      port: port,
    );
  }

  final int family;
  final List<int> address;
  final int port;

  List<int> get ipv4Octets => address.take(4).toList(growable: false);
}

class EmbeddedNodeAction {
  EmbeddedNodeAction({
    required this.kind,
    this.socketAddress,
    List<int> data = const <int>[],
    this.addressCount = 0,
    this.networkId = 0,
    this.packetId = 0,
    this.typeId = 0,
    List<int> ztAddress = const <int>[0, 0, 0, 0, 0],
    List<int> srcMac = const <int>[0, 0, 0, 0, 0, 0],
    List<int> destMac = const <int>[0, 0, 0, 0, 0, 0],
    this.ethertype = 0,
    this.utility = 0,
  }) : data = List<int>.unmodifiable(data),
       ztAddress = List<int>.unmodifiable(ztAddress),
       srcMac = List<int>.unmodifiable(srcMac),
       destMac = List<int>.unmodifiable(destMac) {
    _checkByteList(data, 'data');
    _checkByteList(ztAddress, 'ztAddress', expectedLength: 5);
    _checkByteList(srcMac, 'srcMac', expectedLength: 6);
    _checkByteList(destMac, 'destMac', expectedLength: 6);
  }

  final EmbeddedNodeActionKind kind;
  final EmbeddedSocketAddress? socketAddress;
  final List<int> data;
  final int addressCount;
  final int networkId;
  final int packetId;
  final int typeId;
  final List<int> ztAddress;
  final List<int> srcMac;
  final List<int> destMac;
  final int ethertype;
  final int utility;

  List<List<int>> get zeroTierAddressList {
    if (addressCount == 0) return const <List<int>>[];
    final expectedLength = addressCount * 5;
    if (data.length != expectedLength) {
      throw EmbeddedNodeException(
        'Action address list has ${data.length} bytes for $addressCount addresses.',
      );
    }
    return List<List<int>>.unmodifiable(
      List<List<int>>.generate(
        addressCount,
        (index) =>
            List<int>.unmodifiable(data.sublist(index * 5, (index + 1) * 5)),
        growable: false,
      ),
    );
  }
}

void _checkByteList(List<int> bytes, String name, {int? expectedLength}) {
  if (expectedLength != null && bytes.length != expectedLength) {
    throw ArgumentError.value(
      bytes.length,
      '$name.length',
      'must be $expectedLength',
    );
  }
  for (final byte in bytes) {
    if (byte < 0 || byte > 255) {
      throw RangeError.range(byte, 0, 255, name);
    }
  }
}

abstract interface class EmbeddedNodeDriver {
  Uint8List address();
  int bootstrap(int nowMs);
  int tick(int nowMs);
  int receivePacket(Uint8List packet, EmbeddedSocketAddress from, int nowMs);
  int sendWhois(List<List<int>> addresses, int nowMs);
  int processVirtualFrame(
    int networkId,
    int ethertype,
    Uint8List payload,
    int nowMs,
  );
  int actionCount();
  EmbeddedNodeAction actionAt(int index);
  void clearActions();
  void close();
}

class EmbeddedNodeSession {
  EmbeddedNodeSession(this._driver);

  final EmbeddedNodeDriver _driver;
  bool _closed = false;

  Uint8List get address {
    _checkOpen();
    return _driver.address();
  }

  List<EmbeddedNodeAction> bootstrap(int nowMs) {
    _checkOpen();
    return _collect(_driver.bootstrap(nowMs));
  }

  List<EmbeddedNodeAction> tick(int nowMs) {
    _checkOpen();
    return _collect(_driver.tick(nowMs));
  }

  List<EmbeddedNodeAction> receivePacket(
    Uint8List packet,
    EmbeddedSocketAddress from,
    int nowMs,
  ) {
    _checkOpen();
    return _collect(_driver.receivePacket(packet, from, nowMs));
  }

  List<EmbeddedNodeAction> sendWhois(List<List<int>> addresses, int nowMs) {
    _checkOpen();
    return _collect(_driver.sendWhois(_normalizeZtAddresses(addresses), nowMs));
  }

  List<EmbeddedNodeAction> processVirtualFrame(
    int networkId,
    int ethertype,
    Uint8List payload,
    int nowMs,
  ) {
    _checkOpen();
    // ZeroTier network ids are u64 values; Dart may surface high-bit ids as
    // negative ints while preserving the bit pattern for the FFI Uint64 call.
    if (ethertype < 0 || ethertype > 0xffff) {
      throw RangeError.range(ethertype, 0, 0xffff, 'ethertype');
    }
    return _collect(
      _driver.processVirtualFrame(networkId, ethertype, payload, nowMs),
    );
  }

  List<EmbeddedNodeAction> get pendingActions {
    _checkOpen();
    return _collect(_driver.actionCount());
  }

  void clearActions() {
    _checkOpen();
    _driver.clearActions();
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _driver.close();
  }

  List<EmbeddedNodeAction> _collect(int count) {
    return List<EmbeddedNodeAction>.generate(
      count,
      _driver.actionAt,
      growable: false,
    );
  }

  void _checkOpen() {
    if (_closed) {
      throw const EmbeddedNodeException('Embedded node session is closed.');
    }
  }
}

List<List<int>> _normalizeZtAddresses(List<List<int>> addresses) {
  return List<List<int>>.unmodifiable(
    List<List<int>>.generate(addresses.length, (index) {
      final address = addresses[index];
      _checkByteList(address, 'addresses[$index]', expectedLength: 5);
      return List<int>.unmodifiable(address);
    }, growable: false),
  );
}
