// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../frb_generated.dart';
import '../lib.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `clone`, `default`, `get_data_interchange_format`, `get_pledge_info`, `send_ca_certs`, `send_enroll_response`, `send_per_trigger`, `send_pvr_trigger`, `send_voucher`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<DataInterchangeFormat>>
abstract class DataInterchangeFormat implements RustOpaqueInterface {}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<DiscoveredPledge>>
abstract class DiscoveredPledge implements RustOpaqueInterface {}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<FFIBLECommunicator>>
abstract class FfibleCommunicator implements RustOpaqueInterface {}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<PledgeCtx>>
abstract class PledgeCtx implements RustOpaqueInterface {}

class FFIBLECommunicatorBuilder {
  final ArcBoxFnVecU8PledgeCtxDartFnFutureVecU8? ffiSendPvrTrigger;
  final ArcBoxFnVecU8PledgeCtxDartFnFutureVecU8? ffiSendPerTrigger;
  final ArcBoxFnVecU8PledgeCtxDartFnFutureVecU8? ffiSendVoucher;
  final ArcBoxFnVecU8PledgeCtxDartFnFutureVecU8? ffiSendCaCerts;
  final ArcBoxFnVecU8PledgeCtxDartFnFutureVecU8? ffiSendEnrollResponse;
  final ArcBoxFnDiscoveredPledgeDartFnFutureString? ffiGetDataInterchangeFormat;
  final ArcBoxFnDiscoveredPledgeDataInterchangeFormatDartFnFutureVecU8?
      ffiGetPledgeInfo;

  const FFIBLECommunicatorBuilder({
    this.ffiSendPvrTrigger,
    this.ffiSendPerTrigger,
    this.ffiSendVoucher,
    this.ffiSendCaCerts,
    this.ffiSendEnrollResponse,
    this.ffiGetDataInterchangeFormat,
    this.ffiGetPledgeInfo,
  });

  Future<FfibleCommunicator> build() => RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderBuild(
        that: this,
      );

  static Future<FFIBLECommunicatorBuilder> init() => RustLib.instance.api
      .crateApiFfiblecommunicatorFfibleCommunicatorBuilderInit();

  Future<FFIBLECommunicatorBuilder> setCaCertsFfi(
          {required FutureOr<Uint8List> Function(Uint8List, PledgeCtx)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetCaCertsFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setDataInterchangeFormatFfi(
          {required FutureOr<String> Function(DiscoveredPledge) callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetDataInterchangeFormatFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setEnrollResponseFfi(
          {required FutureOr<Uint8List> Function(Uint8List, PledgeCtx)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetEnrollResponseFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setPerFfi(
          {required FutureOr<Uint8List> Function(Uint8List, PledgeCtx)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetPerFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setPledgeInfoFfi(
          {required FutureOr<Uint8List> Function(
                  DiscoveredPledge, DataInterchangeFormat)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetPledgeInfoFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setPvrFfi(
          {required FutureOr<Uint8List> Function(Uint8List, PledgeCtx)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetPvrFfi(
              that: this, callback: callback);

  Future<FFIBLECommunicatorBuilder> setVoucherFfi(
          {required FutureOr<Uint8List> Function(Uint8List, PledgeCtx)
              callback}) =>
      RustLib.instance.api
          .crateApiFfiblecommunicatorFfibleCommunicatorBuilderSetVoucherFfi(
              that: this, callback: callback);

  @override
  int get hashCode =>
      ffiSendPvrTrigger.hashCode ^
      ffiSendPerTrigger.hashCode ^
      ffiSendVoucher.hashCode ^
      ffiSendCaCerts.hashCode ^
      ffiSendEnrollResponse.hashCode ^
      ffiGetDataInterchangeFormat.hashCode ^
      ffiGetPledgeInfo.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is FFIBLECommunicatorBuilder &&
          runtimeType == other.runtimeType &&
          ffiSendPvrTrigger == other.ffiSendPvrTrigger &&
          ffiSendPerTrigger == other.ffiSendPerTrigger &&
          ffiSendVoucher == other.ffiSendVoucher &&
          ffiSendCaCerts == other.ffiSendCaCerts &&
          ffiSendEnrollResponse == other.ffiSendEnrollResponse &&
          ffiGetDataInterchangeFormat == other.ffiGetDataInterchangeFormat &&
          ffiGetPledgeInfo == other.ffiGetPledgeInfo;
}
