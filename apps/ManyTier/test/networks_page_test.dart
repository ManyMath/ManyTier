import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:manyui/manyui.dart';
import 'package:manytier_app/src/api/manytier_client.dart';
import 'package:manytier_app/src/embedded/embedded_virtual_network.dart';
import 'package:manytier_app/src/networks/networks_page.dart';
import 'package:manytier_app/src/state/connection.dart';
import 'package:manytier_app/src/state/embedded_runtime_lifecycle.dart';
import 'package:manytier_app/src/state/service_lifecycle.dart';
import 'package:manytier_app/src/state/service_registration.dart';

import 'fakes/fake_manytier_client.dart';
import 'fakes/fake_embedded_runtime_starter.dart';
import 'fakes/fake_embedded_virtual_network.dart';
import 'fakes/fake_service_registrar.dart';
import 'fakes/fake_service_starter.dart';

Widget _app(
  FakeManyTierClient client, {
  FakeServiceRegistrar? registrar,
  List<Override> overrides = const <Override>[],
}) {
  final serviceRegistrar = registrar ?? FakeServiceRegistrar(supported: false);
  return ProviderScope(
    overrides: <Override>[
      manyTierClientProvider.overrideWithValue(client),
      manyTierServiceRegistrarProvider.overrideWithValue(serviceRegistrar),
      ...overrides,
    ],
    child: const MWidgetsApp(
      debugShowCheckedModeBanner: false,
      home: NetworksPage(),
    ),
  );
}

Future<void> _settle(WidgetTester tester) async {
  for (int i = 0; i < 8; i++) {
    await tester.pump();
  }
}

Future<void> _useTallSurface(WidgetTester tester) =>
    tester.binding.setSurfaceSize(const Size(900, 2600));

Finder _textFieldWithPlaceholder(String placeholder) {
  return find.byWidgetPredicate(
    (Widget w) => w is MTextField && w.placeholder == placeholder,
  );
}

ControllerNetwork _controllerNetwork({
  String id = 'abcdef0123000001',
  String name = 'Earth',
}) {
  return ControllerNetwork(
    id: id,
    name: name,
    private: true,
    creationTime: 0,
    revision: 1,
    multicastLimit: 32,
    mtu: 2800,
    v4AssignMode: const <String, dynamic>{'zt': true},
    v6AssignMode: const <String, dynamic>{
      'zt': false,
      '6plane': false,
      'rfc4193': false,
    },
    ipAssignmentPools: const <ControllerIpPool>[
      ControllerIpPool(
        ipRangeStart: '10.147.17.1',
        ipRangeEnd: '10.147.17.254',
      ),
    ],
    enableBroadcast: true,
    routes: const <ControllerRoute>[
      ControllerRoute(target: '10.147.17.0/24', via: null),
    ],
    rules: const <Map<String, dynamic>>[],
    capabilities: const <Map<String, dynamic>>[],
    tags: const <Map<String, dynamic>>[],
  );
}

ControllerMember _controllerMember({
  String id = 'feedface01',
  String networkId = 'abcdef0123000001',
  bool authorized = false,
  List<String> ipAssignments = const <String>[],
}) {
  return ControllerMember(
    id: id,
    networkId: networkId,
    authorized: authorized,
    ipAssignments: ipAssignments,
    creationTime: 0,
    lastSeen: 0,
    name: 'Laptop',
    revision: 1,
    activeBridge: false,
    noAutoAssignIps: false,
    lastAuthorizedTime: 0,
    lastDeauthorizedTime: 0,
    vMajor: -1,
    vMinor: -1,
    vRev: -1,
    vProto: -1,
    capabilities: const <int>[],
    tags: const <ControllerTag>[],
  );
}

void main() {
  group('NetworksPage service lifecycle', () {
    testWidgets('starts the local daemon from the not-running card', (
      tester,
    ) async {
      final starter = FakeServiceStarter();
      final client = FakeManyTierClient(
        statusError: const ServiceUnreachable('connection refused'),
      );

      await tester.pumpWidget(
        _app(
          client,
          overrides: <Override>[
            manyTierServiceStarterProvider.overrideWithValue(starter),
          ],
        ),
      );
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Service not running'), findsWidgets);
      expect(
        find.textContaining('--data-dir /tmp/manytier-test'),
        findsOneWidget,
      );

      final start = find.widgetWithText(MButton, 'Start service');
      expect(tester.widget<MButton>(start).onPressed, isNotNull);
      await tester.tap(start);
      client.statusError = null;
      await tester.pump(const Duration(milliseconds: 250));
      await _settle(tester);

      expect(starter.starts, hasLength(1));
      expect(starter.starts.single.apiPort, 9993);
      expect(find.text('Managed service'), findsOneWidget);
      expect(find.text('PID 4242'), findsOneWidget);

      final stop = find.widgetWithText(MButton, 'Stop service');
      expect(tester.widget<MButton>(stop).onPressed, isNotNull);
      await tester.tap(stop);
      await _settle(tester);

      expect(starter.stops, 1);
      expect(find.text('Managed service'), findsNothing);
    });

    testWidgets('installs and removes the login service from onboarding', (
      tester,
    ) async {
      final starter = FakeServiceStarter();
      final registrar = FakeServiceRegistrar();
      final client = FakeManyTierClient(
        statusError: const ServiceUnreachable('connection refused'),
      );

      await tester.pumpWidget(
        _app(
          client,
          registrar: registrar,
          overrides: <Override>[
            manyTierServiceStarterProvider.overrideWithValue(starter),
          ],
        ),
      );
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Login service is not installed.'), findsOneWidget);
      final install = find.widgetWithText(MButton, 'Install at login');
      expect(tester.widget<MButton>(install).onPressed, isNotNull);

      client.statusError = null;
      await tester.tap(install);
      await tester.pump(const Duration(milliseconds: 250));
      await _settle(tester);

      expect(registrar.installs, hasLength(1));
      expect(registrar.installs.single.apiPort, 9993);
      expect(find.text('Login service'), findsOneWidget);
      expect(find.text('Loaded'), findsOneWidget);

      final remove = find.widgetWithText(MButton, 'Remove login service');
      expect(tester.widget<MButton>(remove).onPressed, isNotNull);
      await tester.tap(remove);
      await _settle(tester);

      expect(registrar.uninstalls, 1);
      expect(find.text('Login service'), findsNothing);
    });

    testWidgets('does not offer local process start for remote connections', (
      tester,
    ) async {
      final starter = FakeServiceStarter();
      final client = FakeManyTierClient(
        statusError: const ServiceUnreachable('connection refused'),
      );

      await tester.pumpWidget(
        _app(
          client,
          overrides: <Override>[
            connectionsProvider.overrideWith(
              (ref) => const <SavedConnection>[
                SavedConnection(
                  id: 'remote',
                  label: 'Remote',
                  host: '192.0.2.10',
                ),
              ],
            ),
            activeConnectionIdProvider.overrideWith((ref) => 'remote'),
            manyTierServiceStarterProvider.overrideWithValue(starter),
          ],
        ),
      );
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.textContaining('only start and stop a local daemon'), findsOneWidget);
      final start = find.widgetWithText(MButton, 'Start service');
      expect(tester.widget<MButton>(start).onPressed, isNull);
      expect(starter.starts, isEmpty);
    });

    testWidgets('starts and stops the embedded runtime from onboarding', (
      tester,
    ) async {
      final embeddedStarter = FakeEmbeddedRuntimeStarter();
      addTearDown(embeddedStarter.dispose);
      final client = FakeManyTierClient(
        statusError: const ServiceUnreachable('connection refused'),
      );

      await tester.pumpWidget(
        _app(
          client,
          overrides: <Override>[
            embeddedRuntimeStarterProvider.overrideWithValue(embeddedStarter),
            embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
              () async => const UnsupportedEmbeddedVirtualNetworkFactory(),
            ),
          ],
        ),
      );
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Embedded runtime'), findsOneWidget);
      expect(find.text('Native VPN/TUN'), findsOneWidget);
      expect(find.text('Unavailable'), findsWidgets);
      expect(
        find.textContaining('Native virtual network devices'),
        findsOneWidget,
      );
      final start = find.widgetWithText(MButton, 'Start embedded node');
      expect(tester.widget<MButton>(start).onPressed, isNotNull);

      await tester.ensureVisible(start);
      await tester.tap(start);
      await _settle(tester);

      expect(embeddedStarter.starts, hasLength(1));
      expect(embeddedStarter.starts.single.dataDir, '/tmp/manytier-test');
      expect(find.text('faa900da4a'), findsOneWidget);

      final stop = find.widgetWithText(MButton, 'Stop embedded node');
      expect(tester.widget<MButton>(stop).onPressed, isNotNull);
      await tester.ensureVisible(stop);
      tester.widget<MButton>(stop).onPressed!();
      await _settle(tester);

      expect(embeddedStarter.closes, 1);
      expect(find.text('faa900da4a'), findsNothing);
    });

    testWidgets('shows native virtual network support when available', (
      tester,
    ) async {
      final embeddedStarter = FakeEmbeddedRuntimeStarter();
      addTearDown(embeddedStarter.dispose);
      final client = FakeManyTierClient(
        statusError: const ServiceUnreachable('connection refused'),
      );

      await tester.pumpWidget(
        _app(
          client,
          overrides: <Override>[
            embeddedRuntimeStarterProvider.overrideWithValue(embeddedStarter),
            embeddedVirtualNetworkFactoryResolverProvider.overrideWithValue(
              () async => FakeEmbeddedVirtualNetworkFactory(),
            ),
          ],
        ),
      );
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Native VPN/TUN'), findsOneWidget);
      expect(find.text('Available'), findsOneWidget);
      expect(find.text('Ready'), findsOneWidget);
    });
  });

  group('NetworksPage peers', () {
    testWidgets('renders peer latency text and trend semantics', (
      tester,
    ) async {
      final semantics = tester.ensureSemantics();

      try {
        final client = FakeManyTierClient(
          peers: const <ManyTierPeer>[
            ManyTierPeer(
              address: '1122334455',
              paths: <ManyTierPeerPath>[
                ManyTierPeerPath(
                  address: '192.0.2.1:9993',
                  active: true,
                  lastReceive: 0,
                ),
              ],
              latency: 42,
              role: 'ROOT',
            ),
          ],
        );

        await tester.pumpWidget(_app(client));
        await _useTallSurface(tester);
        await _settle(tester);

        expect(find.text('1122334455'), findsOneWidget);
        expect(find.text('42 ms'), findsOneWidget);
        expect(find.text('1 path'), findsOneWidget);
        expect(
          find.bySemanticsLabel('Latency trend for 1122334455'),
          findsOneWidget,
        );
      } finally {
        semantics.dispose();
      }
    });
  });

  group('NetworksPage controller UI', () {
    testWidgets('lists controller networks and members', (tester) async {
      final client = FakeManyTierClient(
        controllerNetworks: <ControllerNetwork>[_controllerNetwork()],
        controllerMembers: <String, List<ControllerMember>>{
          'abcdef0123000001': <ControllerMember>[
            _controllerMember(ipAssignments: const <String>['10.147.17.20']),
          ],
        },
      );

      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      expect(find.text('Controller'), findsOneWidget);
      expect(find.text('Earth'), findsOneWidget);
      expect(find.text('abcdef0123000001'), findsOneWidget);
      expect(find.text('Laptop'), findsOneWidget);
      expect(find.text('feedface01'), findsOneWidget);
      expect(find.text('Pending'), findsOneWidget);
      expect(find.text('10.147.17.20'), findsOneWidget);
    });

    testWidgets('authorizes a member and edits IP assignments', (tester) async {
      final client = FakeManyTierClient(
        controllerNetworks: <ControllerNetwork>[_controllerNetwork()],
        controllerMembers: <String, List<ControllerMember>>{
          'abcdef0123000001': <ControllerMember>[_controllerMember()],
        },
      );

      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      final authorize = find.widgetWithText(MButton, 'Authorize');
      await tester.ensureVisible(authorize);
      await tester.tap(authorize);
      await _settle(tester);

      expect(find.text('Authorized'), findsOneWidget);

      final editIps = find.widgetWithText(MButton, 'Edit IPs');
      await tester.ensureVisible(editIps);
      await tester.tap(editIps);
      await _settle(tester);
      await tester.enterText(
        _textFieldWithPlaceholder('IP assignments'),
        '10.147.17.30\n10.147.17.31',
      );
      await tester.pump();
      await tester.tap(find.widgetWithText(MButton, 'Save'));
      await _settle(tester);

      expect(find.text('10.147.17.30  10.147.17.31'), findsOneWidget);
    });

    testWidgets('creates and deletes a controller network', (tester) async {
      final client = FakeManyTierClient();

      await tester.pumpWidget(_app(client));
      await _useTallSurface(tester);
      await _settle(tester);

      final create = find.widgetWithText(MButton, 'Create');
      expect(tester.widget<MButton>(create).onPressed, isNull);

      await tester.enterText(
        _textFieldWithPlaceholder('10-digit node address'),
        'abcdef0123',
      );
      await tester.enterText(_textFieldWithPlaceholder('Network name'), 'Lab');
      await tester.pump();

      expect(tester.widget<MButton>(create).onPressed, isNotNull);
      await tester.ensureVisible(create);
      await tester.tap(create);
      await _settle(tester);

      expect(find.text('Lab'), findsOneWidget);
      expect(find.text('abcdef0123000001'), findsOneWidget);

      final delete = find.widgetWithText(MButton, 'Delete');
      await tester.ensureVisible(delete);
      await tester.tap(delete);
      await _settle(tester);
      await tester.tap(find.widgetWithText(MButton, 'Delete').last);
      await _settle(tester);

      expect(find.text('Lab'), findsNothing);
      expect(find.text('No controller networks.'), findsOneWidget);
    });
  });
}
