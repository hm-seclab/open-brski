// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: unused_import, unused_element, unnecessary_import, duplicate_ignore, invalid_use_of_internal_member, annotate_overrides, non_constant_identifier_names, curly_braces_in_flow_control_structures, prefer_const_literals_to_create_immutables, unused_field

// Static analysis wrongly picks the IO variant, thus ignore this
// ignore_for_file: argument_type_not_assignable

import 'api/bootstrapper.dart';
import 'api/config.dart';
import 'api/ffiblecommunicator.dart';
import 'api/identifiers.dart';
import 'api/init.dart';
import 'dart:async';
import 'dart:convert';
import 'frb_generated.dart';
import 'lib.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated_web.dart';

abstract class RustLibApiImplPlatform extends BaseApiImpl<RustLibWire> {
  RustLibApiImplPlatform({
    required super.handler,
    required super.wire,
    required super.generalizedFrbRustBinding,
    required super.portManager,
  });

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_ArcBoxFnStringPledgeCtxDartFnFutureStringPtr =>
          wire.rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_ArcBoxFnVecU8PledgeCtxDartFnFutureStringPtr =>
          wire.rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_BootstrapperPtr => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_FfibleCommunicatorPtr => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_ParsedConfigPtr => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_PledgeCtxPtr =>
      wire.rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx;

  @protected
  AnyhowException dco_decode_AnyhowException(dynamic raw);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  Bootstrapper
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          dynamic raw);

  @protected
  FfibleCommunicator
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          dynamic raw);

  @protected
  ParsedConfig
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          dynamic raw);

  @protected
  PledgeCtx
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          dynamic raw);

  @protected
  FutureOr<String> Function(String, PledgeCtx)
      dco_decode_DartFn_Inputs_String_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx_Output_String_AnyhowException(
          dynamic raw);

  @protected
  FutureOr<String> Function(Uint8List, PledgeCtx)
      dco_decode_DartFn_Inputs_list_prim_u_8_strict_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx_Output_String_AnyhowException(
          dynamic raw);

  @protected
  Object dco_decode_DartOpaque(dynamic raw);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  Bootstrapper
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          dynamic raw);

  @protected
  FfibleCommunicator
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          dynamic raw);

  @protected
  ParsedConfig
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          dynamic raw);

  @protected
  PledgeCtx
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          dynamic raw);

  @protected
  RustStreamSink<String> dco_decode_StreamSink_String_Sse(dynamic raw);

  @protected
  String dco_decode_String(dynamic raw);

  @protected
  BleIdentifiers dco_decode_ble_identifiers(dynamic raw);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      dco_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      dco_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  BleIdentifiers dco_decode_box_autoadd_ble_identifiers(dynamic raw);

  @protected
  FFIBLECommunicatorBuilder dco_decode_box_autoadd_ffible_communicator_builder(
      dynamic raw);

  @protected
  Identifier dco_decode_box_autoadd_identifier(dynamic raw);

  @protected
  FFIBLECommunicatorBuilder dco_decode_ffible_communicator_builder(dynamic raw);

  @protected
  Identifier dco_decode_identifier(dynamic raw);

  @protected
  Uint8List dco_decode_list_prim_u_8_strict(dynamic raw);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString?
      dco_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString?
      dco_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          dynamic raw);

  @protected
  int dco_decode_u_8(dynamic raw);

  @protected
  void dco_decode_unit(dynamic raw);

  @protected
  BigInt dco_decode_usize(dynamic raw);

  @protected
  AnyhowException sse_decode_AnyhowException(SseDeserializer deserializer);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  Bootstrapper
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          SseDeserializer deserializer);

  @protected
  FfibleCommunicator
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          SseDeserializer deserializer);

  @protected
  ParsedConfig
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          SseDeserializer deserializer);

  @protected
  PledgeCtx
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          SseDeserializer deserializer);

  @protected
  Object sse_decode_DartOpaque(SseDeserializer deserializer);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  Bootstrapper
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          SseDeserializer deserializer);

  @protected
  FfibleCommunicator
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          SseDeserializer deserializer);

  @protected
  ParsedConfig
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          SseDeserializer deserializer);

  @protected
  PledgeCtx
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          SseDeserializer deserializer);

  @protected
  RustStreamSink<String> sse_decode_StreamSink_String_Sse(
      SseDeserializer deserializer);

  @protected
  String sse_decode_String(SseDeserializer deserializer);

  @protected
  BleIdentifiers sse_decode_ble_identifiers(SseDeserializer deserializer);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString
      sse_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString
      sse_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  BleIdentifiers sse_decode_box_autoadd_ble_identifiers(
      SseDeserializer deserializer);

  @protected
  FFIBLECommunicatorBuilder sse_decode_box_autoadd_ffible_communicator_builder(
      SseDeserializer deserializer);

  @protected
  Identifier sse_decode_box_autoadd_identifier(SseDeserializer deserializer);

  @protected
  FFIBLECommunicatorBuilder sse_decode_ffible_communicator_builder(
      SseDeserializer deserializer);

  @protected
  Identifier sse_decode_identifier(SseDeserializer deserializer);

  @protected
  Uint8List sse_decode_list_prim_u_8_strict(SseDeserializer deserializer);

  @protected
  ArcBoxFnStringPledgeCtxDartFnFutureString?
      sse_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  ArcBoxFnVecU8PledgeCtxDartFnFutureString?
      sse_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          SseDeserializer deserializer);

  @protected
  int sse_decode_u_8(SseDeserializer deserializer);

  @protected
  void sse_decode_unit(SseDeserializer deserializer);

  @protected
  BigInt sse_decode_usize(SseDeserializer deserializer);

  @protected
  int sse_decode_i_32(SseDeserializer deserializer);

  @protected
  bool sse_decode_bool(SseDeserializer deserializer);

  @protected
  void sse_encode_AnyhowException(
      AnyhowException self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnStringPledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnVecU8PledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          Bootstrapper self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          FfibleCommunicator self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          ParsedConfig self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          PledgeCtx self, SseSerializer serializer);

  @protected
  void
      sse_encode_DartFn_Inputs_String_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx_Output_String_AnyhowException(
          FutureOr<String> Function(String, PledgeCtx) self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_DartFn_Inputs_list_prim_u_8_strict_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx_Output_String_AnyhowException(
          FutureOr<String> Function(Uint8List, PledgeCtx) self,
          SseSerializer serializer);

  @protected
  void sse_encode_DartOpaque(Object self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnStringPledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnVecU8PledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          Bootstrapper self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          FfibleCommunicator self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          ParsedConfig self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          PledgeCtx self, SseSerializer serializer);

  @protected
  void sse_encode_StreamSink_String_Sse(
      RustStreamSink<String> self, SseSerializer serializer);

  @protected
  void sse_encode_String(String self, SseSerializer serializer);

  @protected
  void sse_encode_ble_identifiers(
      BleIdentifiers self, SseSerializer serializer);

  @protected
  void
      sse_encode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnStringPledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnVecU8PledgeCtxDartFnFutureString self,
          SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_ble_identifiers(
      BleIdentifiers self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_ffible_communicator_builder(
      FFIBLECommunicatorBuilder self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_identifier(
      Identifier self, SseSerializer serializer);

  @protected
  void sse_encode_ffible_communicator_builder(
      FFIBLECommunicatorBuilder self, SseSerializer serializer);

  @protected
  void sse_encode_identifier(Identifier self, SseSerializer serializer);

  @protected
  void sse_encode_list_prim_u_8_strict(
      Uint8List self, SseSerializer serializer);

  @protected
  void
      sse_encode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnStringPledgeCtxDartFnFutureString? self,
          SseSerializer serializer);

  @protected
  void
      sse_encode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          ArcBoxFnVecU8PledgeCtxDartFnFutureString? self,
          SseSerializer serializer);

  @protected
  void sse_encode_u_8(int self, SseSerializer serializer);

  @protected
  void sse_encode_unit(void self, SseSerializer serializer);

  @protected
  void sse_encode_usize(BigInt self, SseSerializer serializer);

  @protected
  void sse_encode_i_32(int self, SseSerializer serializer);

  @protected
  void sse_encode_bool(bool self, SseSerializer serializer);
}

// Section: wire_class

class RustLibWire implements BaseWire {
  RustLibWire.fromExternalLibrary(ExternalLibrary lib);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
              ptr);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
              ptr);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
              ptr);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
              ptr);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
              ptr);

  void rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          int ptr) =>
      wasmModule
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
              ptr);

  void rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          int ptr) =>
      wasmModule
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
              ptr);
}

@JS('wasm_bindgen')
external RustLibWasmModule get wasmModule;

@JS()
@anonymous
extension type RustLibWasmModule._(JSObject _) implements JSObject {
  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnStringPledgeCtxDartFnFutureStringSyncSend(
          int ptr);

  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerArcBoxdynFnVecu8PledgeCtxDartFnFutureStringSyncSend(
          int ptr);

  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerBootstrapper(
          int ptr);

  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerFFIBLECommunicator(
          int ptr);

  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerParsedConfig(
          int ptr);

  external void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          int ptr);

  external void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerPledgeCtx(
          int ptr);
}
