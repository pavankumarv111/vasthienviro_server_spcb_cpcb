# Copyright (c) 2017, 2020, Oracle and/or its affiliates.
#
# Following empty comments are intentional.
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
# End empty comments.


# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: mysqlx_notice.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from mysqlx.protobuf import mysqlx_datatypes_pb2 as mysqlx__datatypes__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='mysqlx_notice.proto',
  package='Mysqlx.Notice',
  syntax='proto2',
  serialized_pb=_b('\n\x13mysqlx_notice.proto\x12\rMysqlx.Notice\x1a\x16mysqlx_datatypes.proto\"\xff\x01\n\x05\x46rame\x12\x0c\n\x04type\x18\x01 \x02(\r\x12\x31\n\x05scope\x18\x02 \x01(\x0e\x32\x1a.Mysqlx.Notice.Frame.Scope:\x06GLOBAL\x12\x0f\n\x07payload\x18\x03 \x01(\x0c\"\x1e\n\x05Scope\x12\n\n\x06GLOBAL\x10\x01\x12\t\n\x05LOCAL\x10\x02\"\x83\x01\n\x04Type\x12\x0b\n\x07WARNING\x10\x01\x12\x1c\n\x18SESSION_VARIABLE_CHANGED\x10\x02\x12\x19\n\x15SESSION_STATE_CHANGED\x10\x03\x12#\n\x1fGROUP_REPLICATION_STATE_CHANGED\x10\x04\x12\x10\n\x0cSERVER_HELLO\x10\x05\"\x85\x01\n\x07Warning\x12\x34\n\x05level\x18\x01 \x01(\x0e\x32\x1c.Mysqlx.Notice.Warning.Level:\x07WARNING\x12\x0c\n\x04\x63ode\x18\x02 \x02(\r\x12\x0b\n\x03msg\x18\x03 \x02(\t\")\n\x05Level\x12\x08\n\x04NOTE\x10\x01\x12\x0b\n\x07WARNING\x10\x02\x12\t\n\x05\x45RROR\x10\x03\"P\n\x16SessionVariableChanged\x12\r\n\x05param\x18\x01 \x02(\t\x12\'\n\x05value\x18\x02 \x01(\x0b\x32\x18.Mysqlx.Datatypes.Scalar\"\xf1\x02\n\x13SessionStateChanged\x12;\n\x05param\x18\x01 \x02(\x0e\x32,.Mysqlx.Notice.SessionStateChanged.Parameter\x12\'\n\x05value\x18\x02 \x03(\x0b\x32\x18.Mysqlx.Datatypes.Scalar\"\xf3\x01\n\tParameter\x12\x12\n\x0e\x43URRENT_SCHEMA\x10\x01\x12\x13\n\x0f\x41\x43\x43OUNT_EXPIRED\x10\x02\x12\x17\n\x13GENERATED_INSERT_ID\x10\x03\x12\x11\n\rROWS_AFFECTED\x10\x04\x12\x0e\n\nROWS_FOUND\x10\x05\x12\x10\n\x0cROWS_MATCHED\x10\x06\x12\x11\n\rTRX_COMMITTED\x10\x07\x12\x12\n\x0eTRX_ROLLEDBACK\x10\t\x12\x14\n\x10PRODUCED_MESSAGE\x10\n\x12\x16\n\x12\x43LIENT_ID_ASSIGNED\x10\x0b\x12\x1a\n\x16GENERATED_DOCUMENT_IDS\x10\x0c\"\xae\x01\n\x1cGroupReplicationStateChanged\x12\x0c\n\x04type\x18\x01 \x02(\r\x12\x0f\n\x07view_id\x18\x02 \x01(\t\"o\n\x04Type\x12\x1a\n\x16MEMBERSHIP_QUORUM_LOSS\x10\x01\x12\x1a\n\x16MEMBERSHIP_VIEW_CHANGE\x10\x02\x12\x16\n\x12MEMBER_ROLE_CHANGE\x10\x03\x12\x17\n\x13MEMBER_STATE_CHANGE\x10\x04\"\r\n\x0bServerHelloB\x1b\n\x17\x63om.mysql.cj.x.protobufH\x03')
  ,
  dependencies=[mysqlx__datatypes__pb2.DESCRIPTOR,])
_sym_db.RegisterFileDescriptor(DESCRIPTOR)



_FRAME_SCOPE = _descriptor.EnumDescriptor(
  name='Scope',
  full_name='Mysqlx.Notice.Frame.Scope',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='GLOBAL', index=0, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LOCAL', index=1, number=2,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=154,
  serialized_end=184,
)
_sym_db.RegisterEnumDescriptor(_FRAME_SCOPE)

_FRAME_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='Mysqlx.Notice.Frame.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='WARNING', index=0, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SESSION_VARIABLE_CHANGED', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SESSION_STATE_CHANGED', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GROUP_REPLICATION_STATE_CHANGED', index=3, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SERVER_HELLO', index=4, number=5,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=187,
  serialized_end=318,
)
_sym_db.RegisterEnumDescriptor(_FRAME_TYPE)

_WARNING_LEVEL = _descriptor.EnumDescriptor(
  name='Level',
  full_name='Mysqlx.Notice.Warning.Level',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NOTE', index=0, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='WARNING', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ERROR', index=2, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=413,
  serialized_end=454,
)
_sym_db.RegisterEnumDescriptor(_WARNING_LEVEL)

_SESSIONSTATECHANGED_PARAMETER = _descriptor.EnumDescriptor(
  name='Parameter',
  full_name='Mysqlx.Notice.SessionStateChanged.Parameter',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='CURRENT_SCHEMA', index=0, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ACCOUNT_EXPIRED', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GENERATED_INSERT_ID', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ROWS_AFFECTED', index=3, number=4,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ROWS_FOUND', index=4, number=5,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ROWS_MATCHED', index=5, number=6,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TRX_COMMITTED', index=6, number=7,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TRX_ROLLEDBACK', index=7, number=9,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PRODUCED_MESSAGE', index=8, number=10,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CLIENT_ID_ASSIGNED', index=9, number=11,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GENERATED_DOCUMENT_IDS', index=10, number=12,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=665,
  serialized_end=908,
)
_sym_db.RegisterEnumDescriptor(_SESSIONSTATECHANGED_PARAMETER)

_GROUPREPLICATIONSTATECHANGED_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='Mysqlx.Notice.GroupReplicationStateChanged.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_QUORUM_LOSS', index=0, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MEMBERSHIP_VIEW_CHANGE', index=1, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MEMBER_ROLE_CHANGE', index=2, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MEMBER_STATE_CHANGE', index=3, number=4,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=974,
  serialized_end=1085,
)
_sym_db.RegisterEnumDescriptor(_GROUPREPLICATIONSTATECHANGED_TYPE)


_FRAME = _descriptor.Descriptor(
  name='Frame',
  full_name='Mysqlx.Notice.Frame',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='Mysqlx.Notice.Frame.type', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='scope', full_name='Mysqlx.Notice.Frame.scope', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=1,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='payload', full_name='Mysqlx.Notice.Frame.payload', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _FRAME_SCOPE,
    _FRAME_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=63,
  serialized_end=318,
)


_WARNING = _descriptor.Descriptor(
  name='Warning',
  full_name='Mysqlx.Notice.Warning',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='level', full_name='Mysqlx.Notice.Warning.level', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=True, default_value=2,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='code', full_name='Mysqlx.Notice.Warning.code', index=1,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='msg', full_name='Mysqlx.Notice.Warning.msg', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _WARNING_LEVEL,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=321,
  serialized_end=454,
)


_SESSIONVARIABLECHANGED = _descriptor.Descriptor(
  name='SessionVariableChanged',
  full_name='Mysqlx.Notice.SessionVariableChanged',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='param', full_name='Mysqlx.Notice.SessionVariableChanged.param', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='Mysqlx.Notice.SessionVariableChanged.value', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=456,
  serialized_end=536,
)


_SESSIONSTATECHANGED = _descriptor.Descriptor(
  name='SessionStateChanged',
  full_name='Mysqlx.Notice.SessionStateChanged',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='param', full_name='Mysqlx.Notice.SessionStateChanged.param', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=1,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='Mysqlx.Notice.SessionStateChanged.value', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _SESSIONSTATECHANGED_PARAMETER,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=539,
  serialized_end=908,
)


_GROUPREPLICATIONSTATECHANGED = _descriptor.Descriptor(
  name='GroupReplicationStateChanged',
  full_name='Mysqlx.Notice.GroupReplicationStateChanged',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='Mysqlx.Notice.GroupReplicationStateChanged.type', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='view_id', full_name='Mysqlx.Notice.GroupReplicationStateChanged.view_id', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _GROUPREPLICATIONSTATECHANGED_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=911,
  serialized_end=1085,
)


_SERVERHELLO = _descriptor.Descriptor(
  name='ServerHello',
  full_name='Mysqlx.Notice.ServerHello',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1087,
  serialized_end=1100,
)

_FRAME.fields_by_name['scope'].enum_type = _FRAME_SCOPE
_FRAME_SCOPE.containing_type = _FRAME
_FRAME_TYPE.containing_type = _FRAME
_WARNING.fields_by_name['level'].enum_type = _WARNING_LEVEL
_WARNING_LEVEL.containing_type = _WARNING
_SESSIONVARIABLECHANGED.fields_by_name['value'].message_type = mysqlx__datatypes__pb2._SCALAR
_SESSIONSTATECHANGED.fields_by_name['param'].enum_type = _SESSIONSTATECHANGED_PARAMETER
_SESSIONSTATECHANGED.fields_by_name['value'].message_type = mysqlx__datatypes__pb2._SCALAR
_SESSIONSTATECHANGED_PARAMETER.containing_type = _SESSIONSTATECHANGED
_GROUPREPLICATIONSTATECHANGED_TYPE.containing_type = _GROUPREPLICATIONSTATECHANGED
DESCRIPTOR.message_types_by_name['Frame'] = _FRAME
DESCRIPTOR.message_types_by_name['Warning'] = _WARNING
DESCRIPTOR.message_types_by_name['SessionVariableChanged'] = _SESSIONVARIABLECHANGED
DESCRIPTOR.message_types_by_name['SessionStateChanged'] = _SESSIONSTATECHANGED
DESCRIPTOR.message_types_by_name['GroupReplicationStateChanged'] = _GROUPREPLICATIONSTATECHANGED
DESCRIPTOR.message_types_by_name['ServerHello'] = _SERVERHELLO

Frame = _reflection.GeneratedProtocolMessageType('Frame', (_message.Message,), dict(
  DESCRIPTOR = _FRAME,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.Frame)
  ))
_sym_db.RegisterMessage(Frame)

Warning = _reflection.GeneratedProtocolMessageType('Warning', (_message.Message,), dict(
  DESCRIPTOR = _WARNING,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.Warning)
  ))
_sym_db.RegisterMessage(Warning)

SessionVariableChanged = _reflection.GeneratedProtocolMessageType('SessionVariableChanged', (_message.Message,), dict(
  DESCRIPTOR = _SESSIONVARIABLECHANGED,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.SessionVariableChanged)
  ))
_sym_db.RegisterMessage(SessionVariableChanged)

SessionStateChanged = _reflection.GeneratedProtocolMessageType('SessionStateChanged', (_message.Message,), dict(
  DESCRIPTOR = _SESSIONSTATECHANGED,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.SessionStateChanged)
  ))
_sym_db.RegisterMessage(SessionStateChanged)

GroupReplicationStateChanged = _reflection.GeneratedProtocolMessageType('GroupReplicationStateChanged', (_message.Message,), dict(
  DESCRIPTOR = _GROUPREPLICATIONSTATECHANGED,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.GroupReplicationStateChanged)
  ))
_sym_db.RegisterMessage(GroupReplicationStateChanged)

ServerHello = _reflection.GeneratedProtocolMessageType('ServerHello', (_message.Message,), dict(
  DESCRIPTOR = _SERVERHELLO,
  __module__ = 'mysqlx_notice_pb2'
  # @@protoc_insertion_point(class_scope:Mysqlx.Notice.ServerHello)
  ))
_sym_db.RegisterMessage(ServerHello)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n\027com.mysql.cj.x.protobufH\003'))
# @@protoc_insertion_point(module_scope)
