import 'package:flutter_app/src/rust/api/bootstrapper.dart';
import 'package:flutter_app/src/rust/api/ffiblecommunicator.dart';
import 'package:flutter_app/src/rust/api/identifiers.dart';
import 'package:flutter_app/src/rust/api/config.dart';
import 'package:flutter/services.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'dart:convert' show utf8;

import 'dart:math';
// split write should be used with caution.
//    1. due to splitting, `characteristic.read()` will return partial data.
//    2. it can only be used *with* response to avoid data loss
//    3. The characteristic must be designed to support split data
extension SplitWrite on BluetoothCharacteristic {
  Future<void> splitWrite(List<int> value, {int timeout = 15}) async {
    int chunk = device.mtuNow - 3; // 3 bytes ble overhead
    for (int i = 0; i < value.length; i += chunk) {
      List<int> subvalue = value.sublist(i, min(i + chunk, value.length));
      try {
        await write(subvalue, withoutResponse: false, timeout: timeout);
      } on FlutterBluePlusException catch(e) {
        print(e);
      }
    }
  }
}


class CharacteristicPair {
  BluetoothCharacteristic write;
  BluetoothCharacteristic read;

  CharacteristicPair(this.read, this.write);
}

class CharacteristicPackage {
  CharacteristicPair tpvr;
  //CharacteristicPair tper;
  //CharacteristicPair voucher;
  //CharacteristicPair caCerts;
  //CharacteristicPair enrollResponse;

  CharacteristicPackage(this.tpvr);
}

Future<CharacteristicPackage> getCharacteristicPackage(List<BluetoothService> services) async {
  BleIdentifiers identifiers = await getIdentifiers();
  
  BluetoothService tpvrService = services.firstWhere((el) => el.uuid.toString() == identifiers.tpvr.uuid);
  BluetoothCharacteristic tpvrRead = tpvrService.characteristics.firstWhere((el) => el.uuid.toString() == identifiers.tpvr.readUuid);
  BluetoothCharacteristic tpvrWrite = tpvrService.characteristics.firstWhere((el) => el.uuid.toString() == identifiers.tpvr.writeUuid);

  var pair = CharacteristicPair(tpvrRead, tpvrWrite);
  return CharacteristicPackage(pair);
}

Future<ParsedConfig> getParsedConfig() async {
  var eeCert = await rootBundle.loadString("assets/certificates/registrar-agent.test-cert");

  var registrarCert = await rootBundle.loadString("assets/certificates/registrar.test-cert");

  var eeKeyNoPass = await rootBundle.loadString("assets/keys/registrar-agent-ec-key.test-key");

  ParsedConfig parsedConfig = await getConfig(eeCert: eeCert, eeKey: eeKeyNoPass, registrarCert: registrarCert);

  return parsedConfig;
}

Future<String> characteristicCallback(CharacteristicPair pair, String payload) async {
  List<int> encoded = utf8.encode(payload);

  await pair.write.splitWrite(encoded);

  List<int> buf = [];
  while (true) {
    var ret = await pair.read.read();
    if(ret.isEmpty) {
      break;
    }
    buf.addAll(ret);
  }
  var decoded = utf8.decode(buf);
  return decoded;
}

Future<Bootstrapper> getPledgeFFIBootstrapper(CharacteristicPackage cpackage) async {
  var builder = await FFIBLECommunicatorBuilder.init();
  builder = await builder.setPvrFfi(callback: (trigger, ctx) => characteristicCallback(cpackage.tpvr, trigger));
  builder = await builder.setPerFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setVoucherFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setCaCertsFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setEnrollResponseFfi(callback: (trigger, ctx) => "Hallo");

  var communicator = await builder.build();

  var config = await getParsedConfig();

  var bootstraper = await Bootstrapper.init(config: config, communicator: communicator);

  return bootstraper;
}

Future<Bootstrapper> getMOCKBootstrapper() async {
  var builder = await FFIBLECommunicatorBuilder.init();
  builder = await builder.setPvrFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setPerFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setVoucherFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setCaCertsFfi(callback: (trigger, ctx) => "Hallo");
  builder = await builder.setEnrollResponseFfi(callback: (trigger, ctx) => "Hallo");

  var communicator = await builder.build();

  var config = await getParsedConfig();

  var bootstraper = await Bootstrapper.init(config: config, communicator: communicator);

  return bootstraper;
}