import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_app/screens/scan_screen.dart';
import 'package:flutter_app/screens/wifi_screen.dart';

class AppDrawer extends StatelessWidget {

  const AppDrawer({super.key});

  @override
  Widget build(BuildContext context) {
    return Drawer(
      child: ListView(
        children: [
          const DrawerHeader(decoration: BoxDecoration(color: Colors.blue), child: Text("Modes")),
          ListTile(
            title: const Text('Bluetooth Low Energy'),
            onTap: () {
              MaterialPageRoute route = MaterialPageRoute(
                  builder: (context) => const ScanScreen(), settings: const RouteSettings(name: '/ScanScreen'));
              Navigator.of(context).push(route);
            },
          ),
          ListTile(
            title: const Text('WiFi'),
            onTap: () {
              MaterialPageRoute route = MaterialPageRoute(
                  builder: (context) => const WifiScreen(), settings: const RouteSettings(name: '/WifiScreen'));
              Navigator.of(context).push(route);
            },
          )
        ],
      ),
    );
  }
}